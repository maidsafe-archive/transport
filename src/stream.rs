//! Defines the `Stream` type and related items.

use std::collections::VecDeque;
use std::io;
use std::net::TcpStream;
use std::sync::{Mutex, Condvar, Arc, mpsc};
use std::sync::atomic::{Ordering, AtomicBool};
use std::fmt;
use std::error;
use std::time::{Instant, Duration};
use std::thread;
use std::io::{Read, Write};

use rand;
use maidsafe_utilities::thread::RaiiThreadJoiner;
use socket_addr::SocketAddr;
use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};
use nat_traversal::{MappingContext, tcp_punch_hole};
use nat_traversal;
use w_result::{WResult, WOk, WErr};
use crossbeam;
use void::Void;

use utils::DisplaySlice;
use endpoint::{Endpoint, ToEndpoints};
use rendezvous_info::{PubRendezvousInfo, PrivRendezvousInfo, PrivTcpInfo, PrivUdpInfo,
                      RENDEZVOUS_INFO_EXPIRY_DURATION_SECS};

/// Contains protocol information about a stream. See the `StreamInfo` type for more info.
pub enum StreamProtocolInfo {
    /// A TCP stream.
    Tcp {
        /// The local address of the TCP stream.
        local_addr: SocketAddr,
        /// The peer's address.
        peer_addr: SocketAddr,
    },
    /// A uTP stream.
    Utp {
        /// The local address of the uTP stream.
        local_addr: SocketAddr,
        /// The peer's address.
        peer_addr: SocketAddr,
    },
}

/// Contains info about a `Stream`. The result of calling `Stream::info`.
pub struct StreamInfo {
    /// Protocol information about the stream.
    pub protocol: StreamProtocolInfo,
    /// The connection id of the stream.
    pub connection_id: u64,
}

impl fmt::Display for StreamInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "#{:016x} [{}]", self.connection_id, self.protocol)
    }
}

impl fmt::Display for StreamProtocolInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            StreamProtocolInfo::Tcp { local_addr, peer_addr }
                => write!(f, "[tcp {:>015} -> {:<015}]", local_addr, peer_addr),
            StreamProtocolInfo::Utp { local_addr, peer_addr }
                => write!(f, "[utp {:>015} -> {:<015}]", local_addr, peer_addr),
        }
    }
}

/// The communication point between the writer thread and the rest of the program.
// This is designed to be similar to what currently exists in crust rather than being designed for
// efficiency. There's probably no point in improving this before the eventual switch to
// non-blocking io.
struct BufferInner {
    /// Queue of outgoing data.
    buf: VecDeque<Vec<u8>>,
    /// Whether the writer thread is still running. Set to false to shut down the thread.
    running: bool,
    /// Whether the writer thread has experienced an error.
    error: Option<io::Error>,
}

/// The write buffer of the stream.
struct Buffer {
    inner: Mutex<BufferInner>,
    condvar: Condvar,
}

/// Contains the inner, protocol-specific part of the stream.
enum StreamInner {
    Tcp {
        stream: TcpStream,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
    },
    /*
    Utp {
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
    }
    */
}

/// A transport-agnostic connection to a remote peer.
pub struct Stream {
    protocol_inner: StreamInner,
    buffer: Arc<Buffer>,
    _writer_thread: RaiiThreadJoiner,
    connection_id: u64,
}

quick_error! {
    /// Errors returned by `Stream::from_tcp_stream`.
    #[derive(Debug)]
    pub enum StreamFromTcpStreamError {
        /// Error getting local address of tcp stream
        LocalAddr(err: io::Error) {
            description("Error getting local address of tcp stream")
            display("Error getting local address of tcp stream: {}", err)
            cause(err)
        }
        /// Error getting peer address of tcp stream
        PeerAddr(err: io::Error) {
            description("Error getting peer address of tcp stream")
            display("Error getting peer address of tcp stream: {}", err)
            cause(err)
        }
        /// Error cloning tcp stream
        CloneStream(err: io::Error) {
            description("Error cloning tcp stream")
            display("Error cloning tcp stream: {}", err)
            cause(err)
        }
    }
}

/// Errors returned by `Stream::direct_connect`.
#[derive(Debug)]
pub enum StreamDirectConnectError<E: error::Error + Send + 'static> {
    /// All connection attempts failed
    AllConnectionsFailed(Vec<StreamDirectConnectEndpointError<E>>),
    /// Timed out while trying to connect.
    TimedOut, 
}

impl<E: error::Error + Send + 'static> error::Error for StreamDirectConnectError<E> {
    fn description(&self) -> &str {
        match *self {
            StreamDirectConnectError::AllConnectionsFailed(..)
                => "All connection attempts failed.",
            StreamDirectConnectError::TimedOut
                => "Direct connect timed out.",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            StreamDirectConnectError::AllConnectionsFailed(ref es) => match es.first() {
                Some(e) => Some(e),
                None => None,
            },
            StreamDirectConnectError::TimedOut => None,
        }
    }
}

impl<E: error::Error + Send + 'static> fmt::Display for StreamDirectConnectError<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            StreamDirectConnectError::AllConnectionsFailed(ref es)
                => write!(f, "All connection attempts failed: {}", DisplaySlice("errors", es)),
            StreamDirectConnectError::TimedOut
                => write!(f, "Direct connect timed out"),
        }
    }
}

/// Errors raised by `Stream::direct_connect` in connecting to a specific endpoint.
#[derive(Debug)]
pub enum StreamDirectConnectEndpointError<E: error::Error + Send + 'static> {
    /// Error parsing endpoint
    ParseEndpoint {
        /// The error returned by `ToEndpoints::to_endpoints`
        err: E,
        /// The connection id of the attempted connection.
        connection_id: u64,
    },
    /// Error connecting to tcp endpoint
    TcpConnect {
        /// The error returned by `TcpStream::connect`
        err: io::Error,
        /// The socket address that a connection was attempted to.
        addr: SocketAddr,
        /// The connection id of the attempted connection.
        connection_id: u64,
    },
    /// Error writing to tcp stream.
    TcpWrite {
        /// IO error raised when writing to tcp stream.
        err: io::Error,
        /// The peer address the stream was connected to.
        addr: SocketAddr,
        /// The connection id of the attempted connection.
        connection_id: u64,
    },
    /// Error reading from tcp stream.
    TcpRead {
        /// IO error raised when reading from tcp stream.
        err: io::Error,
        /// The peer address the stream was connected to.
        addr: SocketAddr,
        /// The connection id of the attempted connection.
        connection_id: u64,
    },
    /// Error setting timeout option on tcp stream
    TcpSetTimeout {
        /// IO error raised when setting socket option.
        err: io::Error,
        /// Address that the tcp stream was connected to.
        addr: SocketAddr,
        /// The connection id of the attempted connection.
        connection_id: u64,
    },
    /// Error creating Stream from TcpStream
    TcpCreateStream {
        /// The error returned by `Stream::from_tcp_stream`.
        err: StreamFromTcpStreamError,
        /// The connection id of the attempted connection.
        connection_id: u64,
    },
    /// Handshake failed.
    HandshakeError {
        /// The connection id of the attempted connection.
        connection_id: u64
    },
}

impl<E: error::Error + Send + 'static> error::Error for StreamDirectConnectEndpointError<E> {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            StreamDirectConnectEndpointError::ParseEndpoint { ref err, .. } => Some(err),
            StreamDirectConnectEndpointError::TcpConnect { ref err, .. } => Some(err),
            StreamDirectConnectEndpointError::TcpWrite { ref err, .. } => Some(err),
            StreamDirectConnectEndpointError::TcpCreateStream { ref err, .. } => Some(err),
            StreamDirectConnectEndpointError::TcpRead { ref err, .. } => Some(err),
            StreamDirectConnectEndpointError::TcpSetTimeout { ref err, .. } => Some(err),
            StreamDirectConnectEndpointError::HandshakeError { .. } => None,
        }
    }

    fn description(&self) -> &str {
        match *self {
            StreamDirectConnectEndpointError::ParseEndpoint { .. }
                => "Error parsing endpoint",
            StreamDirectConnectEndpointError::TcpConnect { .. }
                => "Error connecting to tcp endpoint",
            StreamDirectConnectEndpointError::TcpWrite { .. }
                => "Error writing to tcp stream",
            StreamDirectConnectEndpointError::TcpCreateStream { .. }
                => "Error creating Stream from TcpStream",
            StreamDirectConnectEndpointError::TcpRead { .. }
                => "Error reading from tcp stream",
            StreamDirectConnectEndpointError::TcpSetTimeout { .. }
                => "Error setting timeout option on tcp stream",
            StreamDirectConnectEndpointError::HandshakeError { .. }
                => "Handshake failed.",
        }
    }
}

impl<E: error::Error + Send + 'static> fmt::Display for StreamDirectConnectEndpointError<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            StreamDirectConnectEndpointError::ParseEndpoint { ref err, connection_id }
                => write!(f, "Error parsing endpoint: #{:016x} {}", connection_id, err),
            StreamDirectConnectEndpointError::TcpConnect { ref err, addr, connection_id }
                => write!(f, "Error connecting to tcp endpoint: {} #{:016x}: {}", addr, connection_id, err),
            StreamDirectConnectEndpointError::TcpWrite { ref err, addr, connection_id }
                => write!(f, "Error writing to tcp stream: {} #{:016x}: {}", addr, connection_id, err),
            StreamDirectConnectEndpointError::TcpCreateStream { ref err, connection_id }
                => write!(f, "Error creating Stream from TcpStream: #{:016x} {}", connection_id, err),
            StreamDirectConnectEndpointError::TcpRead { ref err, addr, connection_id }
                => write!(f, "Error reading from tcp stream: {} #{:016x}: {}", addr, connection_id, err),
            StreamDirectConnectEndpointError::TcpSetTimeout { ref err, addr, connection_id }
                => write!(f, "Error setting timeout option on tcp stream: {} #{:016x}: {}", addr, connection_id, err),
            StreamDirectConnectEndpointError::HandshakeError { connection_id }
                => write!(f, "Handshake failed: #{:016x}", connection_id),
        }
    }
}

quick_error! {
    /// Warnings raised by `Stream::rendezvous_connect`
    #[derive(Debug)]
    pub enum StreamRendezvousConnectWarning {
        /// Warning raised when doing tcp hole punching
        TcpPunchHole(w: nat_traversal::TcpPunchHoleWarning) {
            description("Warning raised when doing tcp hole punching.")
            display("Warning raised when doing tcp hole punching: {}", w)
            cause(w)
        }
    }
}

quick_error! {
    /// Errors raised by `Stream::rendezvous_connect`
    #[derive(Debug)]
    pub enum StreamRendezvousConnectTcpError {
        /// Error creating tcp stream
        CreateStream(err: StreamFromTcpStreamError) {
            description("Error creating tcp stream")
            display("Error creating tcp stream: {}", err)
            cause(err)
        }
        /// Error doing tcp hole punching
        PunchHole(err: nat_traversal::TcpPunchHoleError) {
            description("Error doing tcp hole punching")
            display("Error doing tcp hole punching")
            cause(err)
        }
    }
}

/// Diagnostic information returned by `Stream::gen_rendezvous_info`. This information may be
/// useful if you are having problems creating rendezvous connections.
#[derive(Debug)]
pub struct StreamGenRendezvousInfoDiagnostics {
    /// Warnings or errors that resulted from attempting to create a mapped tcp socket.
    pub tcp_diags: WResult<(), nat_traversal::MappedTcpSocketMapWarning,
                               nat_traversal::MappedTcpSocketNewError>,
    /// Warnings or errors that resulted from attempting to create a mapped udp socket.
    pub udp_diags: WResult<(), nat_traversal::MappedUdpSocketMapWarning,
                               nat_traversal::MappedUdpSocketNewError>,
}

impl fmt::Display for StreamGenRendezvousInfoDiagnostics {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {

        try!(write!(f, "gen_rendezvous_info diagnostic info:"));
        match self.tcp_diags {
            WOk((), ref ws) => try!(write!(f, " tcp {}.", DisplaySlice("warning", &ws[..]))),
            WErr(ref e) => try!(write!(f, " tcp error: {}.", e)),
        };
        match self.udp_diags {
            WOk((), ref ws) => try!(write!(f, " udp {}.", DisplaySlice("warning", &ws[..]))),
            WErr(ref e) => try!(write!(f, " udp error: {}.", e)),
        };
        Ok(())
    }
}

#[derive(Debug)]
/// Errors returned by `Stream::rendezvous_connect`.
pub enum StreamRendezvousConnectError {
    /// The supplied rendezvous info has expired.
    Expired,

    /// Failed to make a rendezvous connection with any protocol.
    AllProtocolsFailed {
        /// The error of the failed tcp rendezvous connect attempt (if any).
        tcp_err: Option<StreamRendezvousConnectTcpError>,
        /// The error (if any) of the failed attempt to directly connect to the peer's listeners.
        direct_err: Option<StreamDirectConnectError<Void>>,
    },
}

impl error::Error for StreamRendezvousConnectError {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            StreamRendezvousConnectError::Expired => None,
            StreamRendezvousConnectError::AllProtocolsFailed { ref tcp_err, ref direct_err } => {
                match *direct_err {
                    Some(ref err) => return Some(err),
                    None => (),
                }
                match *tcp_err {
                    Some(ref err) => return Some(err),
                    None => (),
                };
                None
            },
        }
    }

    fn description(&self) -> &str {
        match *self {
            StreamRendezvousConnectError::Expired => "The supplied rendezvous info has expired",
            StreamRendezvousConnectError::AllProtocolsFailed { ref tcp_err, ref direct_err } => {
                match (direct_err, tcp_err) {
                    (&Some(..), &Some(..))
                        => "Error making direct connection and tcp rendezvous connection",
                    (&Some(..), &None)
                        => "Error making direct connection",
                    (&None, &Some(..))
                        => "Error making tcp rendezvous connection",
                    (&None, &None) 
                        => "Could not attempt a tcp rendezvous connection due to incompatible \
                            rendezvous infos",
                }
            },
        }
    }
}

impl fmt::Display for StreamRendezvousConnectError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            StreamRendezvousConnectError::Expired => write!(f, "The supplied rendezvous info has expired"),
            StreamRendezvousConnectError::AllProtocolsFailed { ref tcp_err, ref direct_err } => {
                match (direct_err, tcp_err) {
                    (&Some(ref direct_err), &Some(ref tcp_err))
                        => write!(f, "Error making direct connection and tcp rendezvous \
                                      connection. Direct connect error: {}; tcp rendezvous \
                                      connect error: {}", direct_err, tcp_err),
                    (&Some(ref direct_err), &None)
                        => write!(f, "Error making direct connection: {}", direct_err),
                    (&None, &Some(ref tcp_err))
                        => write!(f, "Error making tcp rendezvous connection: {}", tcp_err),
                    (&None, &None) 
                        => write!(f, "Could not attempt a tcp rendezvous connection due to \
                                      incompatible rendezvous infos"),
                }
            },
        }
    }
}

impl Stream {
    /// Retreive information about this stream.
    pub fn info(&self) -> StreamInfo {
        match self.protocol_inner {
            StreamInner::Tcp {
                local_addr,
                peer_addr,
                ..
            } => StreamInfo {
                protocol: StreamProtocolInfo::Tcp {
                    local_addr: local_addr,
                    peer_addr: peer_addr,
                },
                connection_id: self.connection_id,
            }
        }
    }

    /// Generate rendezvous info which can be used to perform a rendezvous connection.
    pub fn gen_rendezvous_info(mc: &MappingContext, deadline: Instant)
            -> (PrivRendezvousInfo, PubRendezvousInfo, StreamGenRendezvousInfoDiagnostics)
    {
        crossbeam::scope(|scope| {
            // Spawn threads so that we can map our tcp and udp sockets in parallel

            let (tcp_result_tx, tcp_result_rx) = mpsc::channel();
            let _ = scope.spawn(move || {
                let res = nat_traversal::MappedTcpSocket::new(mc, deadline);
                let _ = tcp_result_tx.send(res);
            });

            let (udp_result_tx, udp_result_rx) = mpsc::channel();
            let _ = scope.spawn(move || {
                let res = nat_traversal::MappedUdpSocket::new(mc, deadline);
                let _ = udp_result_tx.send(res);
            });

            // Collect the results
            
            let mut priv_tcp_info_opt = None;
            let mut pub_tcp_info_opt = None;
            // Safe to use unwrap_result! here as the only way recv() could return Err is if the
            // mapping thread panicked.
            let tcp_diags = unwrap_result!(tcp_result_rx.recv()).map(|mapped_tcp_socket| {
                let tcp_endpoints = mapped_tcp_socket.endpoints;
                let (priv_tcp, pub_tcp) = nat_traversal::gen_rendezvous_info(tcp_endpoints);

                priv_tcp_info_opt = Some(PrivTcpInfo {
                    socket: mapped_tcp_socket.socket,
                    info: priv_tcp,
                });
                pub_tcp_info_opt = Some(pub_tcp);
            });

            let mut priv_udp_info_opt = None;
            let mut pub_udp_info_opt = None;
            // Safe to use unwrap_result! here as the only way recv() could return Err is if the
            // mapping thread panicked.
            let udp_diags = unwrap_result!(udp_result_rx.recv()).map(|mapped_udp_socket| {
                let udp_endpoints = mapped_udp_socket.endpoints;
                let (priv_udp, pub_udp) = nat_traversal::gen_rendezvous_info(udp_endpoints);

                priv_udp_info_opt = Some(PrivUdpInfo {
                    socket: mapped_udp_socket.socket,
                    info: priv_udp,
                });
                pub_udp_info_opt = Some(pub_udp);
            });

            let connection_id_half = rand::random();
            let priv_info = PrivRendezvousInfo {
                priv_tcp_info: priv_tcp_info_opt,
                priv_udp_info: priv_udp_info_opt,
                connection_id_half: connection_id_half,
                creation_time: Instant::now(),
            };
            let pub_info = PubRendezvousInfo {
                pub_tcp_info: pub_tcp_info_opt,
                pub_udp_info: pub_udp_info_opt,
                connection_id_half: connection_id_half,
                static_endpoints: Vec::new(),
            };
            let diagnostics = StreamGenRendezvousInfoDiagnostics {
                tcp_diags: tcp_diags,
                udp_diags: udp_diags,
            };

            (priv_info, pub_info, diagnostics)
        })
    }

    /// Perform a rendezvous connection.
    pub fn rendezvous_connect(our_priv_info: PrivRendezvousInfo, 
                              their_pub_info: PubRendezvousInfo,
                              deadline: Instant)
            -> WResult<Stream, StreamRendezvousConnectWarning, StreamRendezvousConnectError>
    {
        let conn_id_part_a = our_priv_info.connection_id_half;
        let conn_id_part_b = their_pub_info.connection_id_half;
        let connection_id = conn_id_part_a.wrapping_add(conn_id_part_b);
        let static_endpoints = their_pub_info.static_endpoints;

        if (Instant::now() - our_priv_info.creation_time) >
            Duration::from_secs(RENDEZVOUS_INFO_EXPIRY_DURATION_SECS)
        {
            return WErr(StreamRendezvousConnectError::Expired);
        }

        let (direct_result_tx, direct_result_rx) = mpsc::channel();
        if static_endpoints.len() > 0 {
            let _ = thread!("Stream::rendezvous_connect direct connect", move || {
                let result = Stream::direct_connect_inner(conn_id_part_b,
                                                          &static_endpoints[..],
                                                          deadline);
                let _ = direct_result_tx.send(result);
            });
        }
        else {
            // Necessary to make sure direct_result_tx has been moved out
            drop(direct_result_tx);
        }

        let (tcp_result_tx, tcp_result_rx) = mpsc::channel();
        match (our_priv_info.priv_tcp_info, their_pub_info.pub_tcp_info) {
            (Some(our_info), Some(their_info)) => {
                let _ = thread!("Stream::rendezvous_connect tcp connect", move || {
                    match tcp_punch_hole(our_info.socket, our_info.info, their_info, deadline) {
                        WOk(tcp_stream, ws) => {
                            let ws = ws.into_iter()
                                       .map(|w| StreamRendezvousConnectWarning::TcpPunchHole(w))
                                       .collect();

                            let stream = match Stream::from_tcp_stream(tcp_stream, connection_id) {
                                Ok(stream) => stream,
                                Err(e) => {
                                    let _ = tcp_result_tx.send(WErr(StreamRendezvousConnectTcpError::CreateStream(e)));
                                    return;
                                },
                            };

                            let _ = tcp_result_tx.send(WOk(stream, ws));
                        },
                        WErr(e) => {
                            let _ = tcp_result_tx.send(WErr(StreamRendezvousConnectTcpError::PunchHole(e)));
                        },
                    };
                });
            },
            _ => drop(tcp_result_tx),
        };

        // Wait and see if any direct connections worked first before using a rendezvous connected
        // stream. It's important that we do this and not just use whichever stream connects first.
        // This way, both sides are will end up keeping the same stream. It's also important that
        // we prioritise direct connections first so that this function is compatible with
        // `Listener::rendezvous_connect`
        
        trace!("Stream::rendezvous_connect waiting for direct connect result");
        let direct_err = match direct_result_rx.recv() {
            Ok(Ok(stream)) => {
                trace!("Stream::rendezvous_connect got direct connection");
                return WOk(stream, Vec::new());
            },
            Ok(Err(e)) => Some(e),
            Err(mpsc::RecvError) => None,
        };

        trace!("Stream::rendezvous_connect waiting for tcp result");
        let tcp_err = match tcp_result_rx.recv() {
            Ok(WOk(stream, ws)) => {
                trace!("Stream::rendezvous_connect got tcp connection");
                return WOk(stream, ws);
            },
            Ok(WErr(e)) => Some(e),
            Err(mpsc::RecvError) => None,
        };
        
        trace!("Stream::rendezvous_connect failed");
        WErr(StreamRendezvousConnectError::AllProtocolsFailed {
            tcp_err: tcp_err,
            direct_err: direct_err,
        })
    }

    /// Performs a direct connect to the endpoints specified by `endpoints`. All connections are
    /// performed in parallel and the first successful connection returns.
    pub fn direct_connect<E>(endpoints: E, deadline: Instant)
                -> Result<Stream, StreamDirectConnectError<E::Err>>
            where E: ToEndpoints
    {
        let connection_id = rand::random();
        Stream::direct_connect_inner(connection_id, endpoints, deadline)
    }

    fn direct_connect_inner<E>(connection_id: u64, endpoints: E, deadline: Instant)
                -> Result<Stream, StreamDirectConnectError<E::Err>>
            where E: ToEndpoints
    {
        let endpoints_iter = endpoints.to_endpoints();
        let stop = Arc::new(AtomicBool::new(false));
        let (result_tx, result_rx) = mpsc::channel();
        let mut num_endpoints = 0;

        // Iterate over all the endpoints and spawn a thread to connect to each one.
        for endpoint_res in endpoints_iter {
            num_endpoints += 1;
            let stop = stop.clone();
            let result_tx = result_tx.clone();

            let _ = thread!("Stream::direct_connect connect", move || {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                let endpoint = match endpoint_res {
                    Ok(endpoint) => endpoint,
                    Err(e) => {
                        let _ = result_tx.send(Some(Err(StreamDirectConnectEndpointError::ParseEndpoint {
                            err: e,
                            connection_id: connection_id,
                        })));
                        return;
                    },
                };
                match endpoint {
                    Endpoint::Tcp(addr) => {
                        if stop.load(Ordering::SeqCst) {
                            return;
                        }
                        let mut tcp_stream = match TcpStream::connect(&*addr) {
                            Ok(tcp_stream) => tcp_stream,
                            Err(e) => {
                                let _ = result_tx.send(Some(Err(StreamDirectConnectEndpointError::TcpConnect {
                                    addr: addr,
                                    err: e,
                                    connection_id: connection_id,
                                })));
                                return;
                            },
                        };
                        if stop.load(Ordering::SeqCst) {
                            return;
                        }
                        match tcp_stream.write_u64::<BigEndian>(connection_id) {
                            Ok(()) => (),
                            Err(e) => {
                                let _ = result_tx.send(Some(Err(StreamDirectConnectEndpointError::TcpWrite {
                                    addr: addr,
                                    err: e,
                                    connection_id: connection_id,
                                })));
                                return;
                            },
                        };
                        if stop.load(Ordering::SeqCst) {
                            return;
                        }
                        match tcp_stream.set_read_timeout(Some(Duration::from_millis(400))) {
                            Ok(()) => (),
                            Err(e) => {
                                let _ = result_tx.send(Some(Err(StreamDirectConnectEndpointError::TcpSetTimeout {
                                    err: e,
                                    addr: addr,
                                    connection_id: connection_id,
                                })));
                                return;
                            },
                        };
                        let recv_connection_id = match tcp_stream.read_u64::<BigEndian>() {
                            Ok(recv_connection_id) => recv_connection_id,
                            Err(e) => {
                                let _ = result_tx.send(Some(Err(StreamDirectConnectEndpointError::TcpWrite {
                                    addr: addr,
                                    err: e,
                                    connection_id: connection_id,
                                })));
                                return;
                            },
                        };
                        if connection_id != recv_connection_id {
                            let _ = result_tx.send(Some(Err(StreamDirectConnectEndpointError::HandshakeError {
                                connection_id: connection_id,
                            })));
                            return;
                        }
                        match tcp_stream.set_read_timeout(None) {
                            Ok(()) => (),
                            Err(e) => {
                                let _ = result_tx.send(Some(Err(StreamDirectConnectEndpointError::TcpSetTimeout {
                                    err: e,
                                    addr: addr,
                                    connection_id: connection_id,
                                })));
                                return;
                            },
                        };
                        if stop.load(Ordering::SeqCst) {
                            return;
                        }
                        let stream = match Stream::from_tcp_stream(tcp_stream, connection_id) {
                            Ok(stream) => stream,
                            Err(e) => {
                                let _ = result_tx.send(Some(Err(StreamDirectConnectEndpointError::TcpCreateStream {
                                    err: e,
                                    connection_id: connection_id,
                                })));
                                return;
                            },
                        };
                        let _ = result_tx.send(Some(Ok(stream)));
                    },
                    Endpoint::Utp(..) => unimplemented!(),
                }
            });
        }
        let timeout_thread = thread!("Stream::direct_connect timeout", move || {
            let now = Instant::now();
            if deadline > now {
                let timeout = deadline - now;
                thread::park_timeout(timeout);
            }
            let _ = result_tx.send(None);
        });

        let mut errors = Vec::new();

        // Loop over the results that are sent back to us and return as soon as we find a
        // successful connection.
        loop {
            // If the number of errors so far is the same as the number of connections we
            // attempted then return an error.
            if errors.len() == num_endpoints {
                stop.store(true, Ordering::SeqCst);
                timeout_thread.thread().unpark();
                return Err(StreamDirectConnectError::AllConnectionsFailed(errors))
            }
            let result = result_rx.recv();
            match result {
                // We got a connection!
                Ok(Some(Ok(stream))) => {
                    stop.store(true, Ordering::SeqCst);
                    timeout_thread.thread().unpark();
                    return Ok(stream);
                },
                // We got an error. Record it.
                Ok(Some(Err(e))) => {
                    errors.push(e);
                },
                // Timed out.
                Ok(None) => {
                    stop.store(true, Ordering::SeqCst);
                    timeout_thread.thread().unpark();
                    return Err(StreamDirectConnectError::TimedOut);
                },
                // Not possible unless all the senders have hung up. Which means worker threads
                // have exited without sending anything. The timer thread must have panicked and
                // at least one of the connecting threads must have panicked aswell.
                Err(mpsc::RecvError) => {
                    panic!("Connecting threads panicked!");
                },
            };
        }
    }

    /// Promote a `TcpStream` to a `Stream` using the given connection id.
    pub fn from_tcp_stream(stream: TcpStream, connection_id: u64) -> Result<Stream, StreamFromTcpStreamError> {
        trace!("Stream::from_tcp_stream(connection_id = #{:016x})", connection_id);
        let local_addr = match stream.local_addr() {
            Ok(local_addr) => local_addr,
            Err(e) => {
                debug!("Error getting local address of tcp stream: {}", e);
                return Err(StreamFromTcpStreamError::LocalAddr(e))
            },
        };
        let peer_addr = match stream.peer_addr() {
            Ok(peer_addr) => peer_addr,
            Err(e) => {
                debug!("Error getting peer address of tcp stream: {}", e);
                return Err(StreamFromTcpStreamError::PeerAddr(e))
            },
        };
        let mut writer_stream = match stream.try_clone() {
            Ok(writer_stream) => writer_stream,
            Err(e) => {
                debug!("Error cloning tcp stream: {}", e);
                return Err(StreamFromTcpStreamError::CloneStream(e))
            },
        };
        let buffer = Arc::new(Buffer {
            inner: Mutex::new(BufferInner {
                buf: VecDeque::new(),
                running: true,
                error: None,
            }),
            condvar: Condvar::new(),
        });
        let buffer_cloned = buffer.clone();

        // This is the tcp stream's writer thread.
        let writer_thread = RaiiThreadJoiner::new(thread!("Stream tcp writer", move || {
            let buffer = buffer_cloned;
            // We loop, reading data from the incoming queue and writing it to the socket.
            loop {
                // First get the next Vec<u8> of data to be written.
                trace!("tcp writer thread checking for fresh data (connection_id == #{:016x})", connection_id);
                let buf;
                {
                    let mut inner = unwrap_result!(buffer.inner.lock());
                    // Loop waiting for fresh data to arrive.
                    loop {
                        match inner.buf.pop_front() {
                            // If there's data to be written, return it through buf and break this
                            // inner loop.
                            Some(b) => {
                                buf = b;
                                break;
                            },
                            // No data to be written. Check to see if we can exit then block until
                            // we get woken up.
                            None => {
                                if !inner.running {
                                    trace!("tcp writer thread exiting normally (connection_id == #{:016x})", connection_id);
                                    return;
                                }
                                trace!("tcp writer thread going to sleep (connection_id == #{:016x})", connection_id);
                                inner = unwrap_result!(buffer.condvar.wait(inner));
                                trace!("tcp writer thread waking up (connection_id == #{:016x})", connection_id);
                            },
                        }
                    };
                };

                let len = buf.len();
                trace!("tcp writer thread writing {} bytes (connection_id == #{:016x})", len, connection_id);
                match writer_stream.write_all(&buf[..]) {
                    Ok(()) => (),
                    Err(e) => {
                        debug!("tcp writer thread exiting due to error (connection_id == #{:016x}): {}", connection_id, e);
                        let mut inner = unwrap_result!(buffer.inner.lock());
                        inner.error = Some(e);
                        return;
                    },
                }
            };
        }));
        Ok(Stream {
            protocol_inner: StreamInner::Tcp {
                stream: stream,
                local_addr: SocketAddr(local_addr),
                peer_addr: SocketAddr(peer_addr),
            },
            buffer: buffer,
            _writer_thread: writer_thread,
            connection_id: connection_id,
        })
    }
    /*
    pub fn from_utp_stream(stream: UtpStream) -> Result<Stream> {

    }
    */
}

impl Drop for Stream {
    fn drop(&mut self) {
        let mut inner = unwrap_result!(self.buffer.inner.lock());

        // Tell the writer thread to shutdown.
        inner.running = false;

        // Wake the writer thread.
        self.buffer.condvar.notify_all();
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.protocol_inner {
            StreamInner::Tcp { ref mut stream, .. } => {
                stream.read(buf)
            },
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut inner = unwrap_result!(self.buffer.inner.lock());
        if let Some(e) = inner.error.take() {
            inner.error = Some(io::Error::new(io::ErrorKind::BrokenPipe, "Stream has closed"));
            return Err(e);
        }
        let len = buf.len();
        inner.buf.push_back(buf.to_owned());
        self.buffer.condvar.notify_all();
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        // TODO(canndrew): This currently doesn't do anything (other than check the error)
        let mut inner = unwrap_result!(self.buffer.inner.lock());
        if let Some(e) = inner.error.take() {
            inner.error = Some(io::Error::new(io::ErrorKind::BrokenPipe, "Stream has closed"));
            return Err(e);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Instant, Duration};
    use std::net::{TcpListener, TcpStream};

    use maidsafe_utilities;
    use nat_traversal::MappingContext;

    use stream::Stream;
    use test_utils::{check_stream, bounce_stream, timebomb};

    #[test]
    pub fn rendezvous_connect() {
        let _ = maidsafe_utilities::log::init(true);

        timebomb(Duration::from_secs(12), || {
            let mc = unwrap_result!(MappingContext::new().result_log());

            let deadline = Instant::now() + Duration::from_secs(2);
            let (priv_info_0, pub_info_0, diags) = Stream::gen_rendezvous_info(&mc, deadline);
            info!("info_0: {}", diags);
            let deadline = Instant::now() + Duration::from_secs(2);
            let (priv_info_1, pub_info_1, diags) = Stream::gen_rendezvous_info(&mc, deadline);
            info!("info_1: {}", diags);
            
            let deadline = Instant::now() + Duration::from_secs(5);
            let thread_0 = thread!("rendezvous_connect 0", move || {
                let mut stream = unwrap_result!(Stream::rendezvous_connect(priv_info_0,
                                                                           pub_info_1,
                                                                           deadline).result_log());
                bounce_stream(&mut stream);
            });

            let thread_1 = thread!("rendezvous_connect 1", move || {
                let mut stream = unwrap_result!(Stream::rendezvous_connect(priv_info_1,
                                                                           pub_info_0,
                                                                           deadline).result_log());
                check_stream(&mut stream);
            });

            unwrap_result!(thread_0.join());
            unwrap_result!(thread_1.join());
        })
    }

    #[test]
    pub fn read_write_tcp() {
        let _ = maidsafe_utilities::log::init(true);

        timebomb(Duration::from_secs(3), || {
            let listener = unwrap_result!(TcpListener::bind("127.0.0.1:0"));
            let addr = unwrap_result!(listener.local_addr());

            let accept_thread = thread!("accept thread", move || {
                let (tcp_stream, _) = unwrap_result!(listener.accept());
                let mut stream = unwrap_result!(Stream::from_tcp_stream(tcp_stream, 1234));
                //let mut stream = tcp_stream;
                
                bounce_stream(&mut stream);
                drop(stream);
                trace!("acceptor thread dropped stream");
                //::std::thread::sleep(Duration::from_millis(500));
            });
            let tcp_stream = unwrap_result!(TcpStream::connect(&addr));
            let mut stream = unwrap_result!(Stream::from_tcp_stream(tcp_stream, 5678));
            //let mut stream = tcp_stream;

            check_stream(&mut stream);

            trace!("connector thread dropping stream");
            drop(stream);
            trace!("connector thread dropped stream");

            unwrap_result!(accept_thread.join());
        })
    }
}

