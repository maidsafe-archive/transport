//! Defines the `Listener` type and related items.

use std::sync::{Arc, Mutex, RwLock, mpsc};
use std::sync::mpsc::{Sender, Receiver};
use std::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;
use std::error;
use std::fmt;
use std::io;
use std::time::{Instant, Duration};
use std::net::TcpStream;
use std::thread;

use maidsafe_utilities::thread::RaiiThreadJoiner;
use nat_traversal::MappingContext;
use nat_traversal;
use lru_time_cache;
use lru_time_cache::LruCache;
use w_result::{WResult, WOk, WErr};
use socket_addr::SocketAddr;
use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};
use crossbeam;

use listen_endpoint::{ListenEndpoint, ToListenEndpoints};
use endpoint::{Endpoint, ToEndpoints};
use stream::{Stream, StreamFromTcpStreamError, StreamGenRendezvousInfoDiagnostics,
             StreamRendezvousConnectWarning, StreamRendezvousConnectError};
use socket_utils;
use rendezvous_info::{PubRendezvousInfo, PrivRendezvousInfo};

/// Errors returned by `Listener::add_external_endpoints`
#[derive(Debug)]
pub enum ListenerAddExternalEndpointsError<E: error::Error> {
    /// Error parsing an endpoint.
    ParseEndpoint(E),
    /// The listener is not listening on the provided listen endpoint.
    UnknownListenEndpoint,
}

impl<E: error::Error> error::Error for ListenerAddExternalEndpointsError<E> {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            ListenerAddExternalEndpointsError::ParseEndpoint(ref err) => Some(err),
            ListenerAddExternalEndpointsError::UnknownListenEndpoint => None,
        }
    }

    fn description(&self) -> &str {
        match *self {
            ListenerAddExternalEndpointsError::ParseEndpoint(..)
                => "Error parsing an endpoint",
            ListenerAddExternalEndpointsError::UnknownListenEndpoint
                => "The listener is not listening on the provided listen endpoint",
        }
    }
}

impl<E: error::Error> fmt::Display for ListenerAddExternalEndpointsError<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ListenerAddExternalEndpointsError::ParseEndpoint(ref err)
                => write!(f, "Error parsing an endpoint: {}", err),
            ListenerAddExternalEndpointsError::UnknownListenEndpoint
                => write!(f, "The listener is not listening on the provided listen endpoint"),
        }
    }
}

quick_error! {
    /// Warnings raised by `Listener::bind`
    #[derive(Debug)]
    pub enum ListenerBindEndpointWarning {
        /// A warning was raised when mapping the listening tcp socket.
        TcpMapWarning(w: nat_traversal::MappedTcpSocketMapWarning) {
            description("Warning raised while mapping tcp socket")
            display("Warning raised while mapping tcp socket: {}", w)
            cause(w)
        }
        /*
        UdpMapWarning(w: nat_traversal::MappedUdpSocketMapWarning) {
            description("Warning raised while mapping udp socket")
            display("Warning raised while mapping udp socket: {}", w)
            cause(w)
        }
        */
    }
}

/// Errors that can be returned when binding to a specific endpoint. Returned in
/// `ListenerBindError`.
#[derive(Debug)]
pub enum ListenerBindEndpointError<E: error::Error> {
    /// Error parsing the endpoint.
    ParseEndpoint(E),

    /// Error binding to local tcp endpoint.
    TcpBind {
        /// The local tcp address that could not be bound.
        local_addr: SocketAddr,

        /// Error raised when trying to bind the address.
        err: nat_traversal::NewReusablyBoundTcpSocketError,
    },

    /// Error mapping tcp socket.
    TcpMap {
        /// The local tcp address of the socket that could not be mapped.
        local_addr: SocketAddr,

        /// The mapping error.
        err: nat_traversal::MappedTcpSocketMapError,
    },

    /// Error listening on tcp socket.
    TcpListen {
        /// The local tcp address of the socket that could be listened on.
        local_addr: SocketAddr,

        /// The io error returned by listen()
        err: io::Error,
    },

    /// Error getting locally bound address of previously bound tcp socket.
    TcpLocalAddr {
        /// The address the socket was bound to.
        local_addr: SocketAddr,

        /// The io error.
        err: io::Error,
    },
}

impl<E: error::Error> error::Error for ListenerBindEndpointError<E> {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            ListenerBindEndpointError::ParseEndpoint(ref err) => Some(err),
            ListenerBindEndpointError::TcpBind { ref err, .. } => Some(err),
            ListenerBindEndpointError::TcpMap { ref err, .. } => Some(err),
            ListenerBindEndpointError::TcpListen { ref err, .. } => Some(err),
            ListenerBindEndpointError::TcpLocalAddr { ref err, .. } => Some(err),
        }
    }

    fn description(&self) -> &str {
        match *self {
            ListenerBindEndpointError::ParseEndpoint(..)
                => "Error parsing endpoint",
            ListenerBindEndpointError::TcpBind { .. }
                => "Error binding to local tcp endpoint",
            ListenerBindEndpointError::TcpMap { .. }
                => "Error mapping tcp socket",
            ListenerBindEndpointError::TcpListen { .. }
                => "Error listening on tcp socket",
            ListenerBindEndpointError::TcpLocalAddr { .. }
                => "Error getting locally bound address of previously bound tcp socket",
        }
    }
}

impl<E: error::Error> fmt::Display for ListenerBindEndpointError<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ListenerBindEndpointError::ParseEndpoint(ref err)
                => write!(f, "Error parsing endpoint: {}", err),
            ListenerBindEndpointError::TcpBind { ref err, ref local_addr }
                => write!(f, "Error binding to local tcp endpoint {}: {}", local_addr, err),
            ListenerBindEndpointError::TcpMap { ref err, ref local_addr }
                => write!(f, "Error mapping tcp socket bound to {}: {}", local_addr, err),
            ListenerBindEndpointError::TcpListen { ref err, ref local_addr }
                => write!(f, "Error listening on tcp socket bound to {}: {}", local_addr, err),
            ListenerBindEndpointError::TcpLocalAddr { ref err, ref local_addr }
                => write!(f, "Error getting locally bound address of tcp socket previously bound \
                              to {}: {}", local_addr, err),
        }
    }
}

quick_error! {
    /// Errors returned by `Listener::accept`.
    #[derive(Debug)]
    #[allow(missing_docs)] // Needed because quick_error! can't parse doc-comments on struct
                           // variant members.
    pub enum ListenerAcceptError {
        /// Error accepting an incoming tcp connection.
        TcpAccept {
            local_addr: SocketAddr,
            err: io::Error,
        } {
            description("IO error accepting an incoming connection.")
            display("IO error accepting an incoming connection on {}: {}", local_addr, err)
            cause(err)
        }
        /// Error setting the timeout option on an incoming tcp stream.
        TcpSetTimeout {
            local_addr: SocketAddr,
            peer_addr: SocketAddr,
            err: io::Error,
        } {
            description("IO error setting timeout on tcp stream")
            display("IO error setting timeout on tcp stream {} <-> {}: {}",
                    local_addr, peer_addr, err)
            cause(err)
        }
        /// Error reading from freshly accepted tcp stream.
        TcpRead {
            local_addr: SocketAddr,
            peer_addr: SocketAddr,
            err: io::Error,
        } {
            description("IO error reading from incoming tcp stream")
            display("IO error reading from incoming tcp stream {} <-> {}: {}",
                    local_addr, peer_addr, err)
            cause(err)
        }
        /// Error writing to freshly accepted tcp stream.
        TcpWrite {
            local_addr: SocketAddr,
            peer_addr: SocketAddr,
            err: io::Error
        } {
            description("IO error writing to incoming tcp stream")
            display("IO error writing to incoming tcp stream {} <-> {}: {}",
                    local_addr, peer_addr, err)
            cause(err)
        }
        /// Error building a `Stream` out of an accepted tcp stream.
        TcpStreamize {
            local_addr: SocketAddr,
            peer_addr: SocketAddr,
            err: StreamFromTcpStreamError
        } {
            description("Error creating stream out of incoming tcp connection")
            display("Error creating stream out of incoming tcp connection {} <-> {}: {}",
                    local_addr, peer_addr, err)
            cause(err)
        }
    }
}

struct SingleListener {
    stop_flag: Arc<AtomicBool>,
    external_endpoints: Vec<Endpoint>,
    local_endpoint: ListenEndpoint,
    _listener_thread: RaiiThreadJoiner,
}

impl Drop for SingleListener {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        match self.local_endpoint {
            ListenEndpoint::Tcp(addr) => {
                let socket_addr = socket_utils::socket_addr_unspecified_to_loopback(*addr);
                // Connect to ourselves to make the listener thread break out of `accept()`.
                // We don't care about the result here because it's possible the listener may have
                // already shut itself down.
                let _ = TcpStream::connect(&socket_addr);
            },
            ListenEndpoint::Utp(..) => unimplemented!(),
        }
    }
}

/// Listens on a set of listen endpoints and accepts incoming connections.
pub struct Listener<M: AsRef<MappingContext> + Send + Clone> {
    mapping_context: M,
    connection_id_filter: Arc<Mutex<LruCache<u64, ()>>>,
    expected_peers_tx: Arc<Mutex<LruCache<u64, Sender<Stream>>>>,
    expected_peers_rx: Arc<Mutex<LruCache<u64, Receiver<Stream>>>>,
    single_listeners: RwLock<HashMap<ListenEndpoint, SingleListener>>,
    incoming_rx: Mutex<Receiver<Option<Result<Stream, ListenerAcceptError>>>>,
    incoming_tx: Mutex<Sender<Option<Result<Stream, ListenerAcceptError>>>>,
}

impl<M> Listener<M>
        where M: AsRef<MappingContext> + Send + Clone
{
    /// Create a new Listener which is not listening on any endpoints.
    pub fn new(mc: M) -> Listener<M> {
        let connection_id_filter = LruCache::with_expiry_duration(Duration::from_secs(20));
        let connection_id_filter = Arc::new(Mutex::new(connection_id_filter));
        let expected_peers_tx = LruCache::with_expiry_duration(Duration::from_secs(60));
        let expected_peers_tx = Arc::new(Mutex::new(expected_peers_tx));
        let expected_peers_rx = LruCache::with_expiry_duration(Duration::from_secs(60));
        let expected_peers_rx = Arc::new(Mutex::new(expected_peers_rx));
        let (incoming_tx, incoming_rx) = mpsc::channel();

        Listener {
            mapping_context: mc,
            connection_id_filter: connection_id_filter,
            expected_peers_tx: expected_peers_tx,
            expected_peers_rx: expected_peers_rx,
            incoming_rx: Mutex::new(incoming_rx),
            incoming_tx: Mutex::new(incoming_tx),
            single_listeners: RwLock::new(HashMap::new()),
        }
    }

    /// Bind to all the endpoints that can be parsed from `listen_endpoints`.
    pub fn bind<E>(&self, listen_endpoints: E, deadline: Instant)
            -> Vec<WResult<ListenEndpoint, ListenerBindEndpointWarning, ListenerBindEndpointError<E::Err>>>
        where E: ToListenEndpoints
    {
        let (results_tx, results_rx) = mpsc::channel();
        let incoming_tx = unwrap_result!(self.incoming_tx.lock()).clone();
        crossbeam::scope(|scope| {
            let listen_endpoints = listen_endpoints.to_listen_endpoints();
            for listen_endpoint_res in listen_endpoints {
                let listen_endpoint = match listen_endpoint_res {
                    Ok(listen_endpoint) => listen_endpoint,
                    Err(e) => {
                        let _ = results_tx.send(WErr(ListenerBindEndpointError::ParseEndpoint(e)));
                        continue;
                    },
                };
                match listen_endpoint {
                    ListenEndpoint::Tcp(addr) => {
                        let tcp_builder_listener = match nat_traversal::new_reusably_bound_tcp_socket(&addr) {
                            Ok(tcp_builder_listener) => tcp_builder_listener,
                            Err(e) => {
                                let _ = results_tx.send(WErr(ListenerBindEndpointError::TcpBind {
                                    local_addr: addr,
                                    err: e,
                                }));
                                continue;
                            },
                        };
                        let results_tx = results_tx.clone();
                        let incoming_tx = incoming_tx.clone();
                        let connection_id_filter = self.connection_id_filter.clone();
                        let expected_peers_tx = self.expected_peers_tx.clone();
                        let mapping_context = self.mapping_context.clone();
                        let _ = scope.spawn(move || {
                            let mut warnings = Vec::new();
                            let mapped_tcp_socket = match nat_traversal::MappedTcpSocket::map(
                                    tcp_builder_listener, mapping_context.as_ref(), deadline
                            ) {
                                WOk(mapped_tcp_socket, ws) => {
                                    warnings.extend(ws.into_iter().map(|w| ListenerBindEndpointWarning::TcpMapWarning(w)));
                                    mapped_tcp_socket
                                },
                                WErr(e) => {
                                    let _ = results_tx.send(WErr(ListenerBindEndpointError::TcpMap {
                                        local_addr: addr,
                                        err: e,
                                    }));
                                    return;
                                },
                            };
                            let tcp_socket = mapped_tcp_socket.socket;
                            let listener = match tcp_socket.listen(1) {
                                Ok(listener) => listener,
                                Err(e) => {
                                    let _ = results_tx.send(WErr(ListenerBindEndpointError::TcpListen {
                                        local_addr: addr,
                                        err: e,
                                    }));
                                    return;
                                },
                            };

                            // TODO(canndrew): This should be fixed to filter out nat-restricted
                            // endpoints.  We should do this once nat_traversal gets better at
                            // detecting nat restriction and doesn't just pessimisticly assume
                            // endpoints are restricted.
                            let addrs: Vec<SocketAddr> = mapped_tcp_socket.endpoints.into_iter()
                                                                                    .map(|m| m.addr)
                                                                                    .collect();
                            let external_endpoints = addrs.into_iter()
                                                          .map(|a| Endpoint::Tcp(a))
                                                          .collect();

                            let actual_port = match listener.local_addr() {
                                Ok(addr) => addr.port(),
                                Err(e) => {
                                    let _ = results_tx.send(WErr(ListenerBindEndpointError::TcpLocalAddr {
                                        local_addr: addr,
                                        err: e,
                                    }));
                                    return;
                                },
                            };
                            
                            let local_addr = SocketAddr::new(addr.ip(), actual_port);
                            let local_endpoint = ListenEndpoint::Tcp(local_addr);
                            let stop_flag = Arc::new(AtomicBool::new(false));
                            let stop_flag_clone = stop_flag.clone();
                            let listener_thread = thread!("Listener::bind acceptor", move || {
                                let stop_flag = stop_flag_clone;
                                loop {
                                    let accept_res = listener.accept();
                                    if stop_flag.load(Ordering::SeqCst) {
                                        break;
                                    };
                                    let (mut tcp_stream, peer_addr) = match accept_res {
                                        Ok(x) => x,
                                        Err(e) => {
                                            let err = ListenerAcceptError::TcpAccept {
                                                local_addr: local_addr,
                                                err: e,
                                            };
                                            let _  = incoming_tx.send(Some(Err(err)));
                                            continue;
                                        },
                                    };
                                    let peer_addr = SocketAddr(peer_addr);
                                    let incoming_tx = incoming_tx.clone();
                                    let connection_id_filter = connection_id_filter.clone();
                                    let expected_peers_tx = expected_peers_tx.clone();
                                    let _ = thread!("Listener::bind accept connection", move || {
                                        let timeout = Duration::from_secs(3);
                                        match tcp_stream.set_read_timeout(Some(timeout)) {
                                            Ok(()) => (),
                                            Err(e) => {
                                                let err = ListenerAcceptError::TcpSetTimeout {
                                                    local_addr: local_addr,
                                                    peer_addr: peer_addr,
                                                    err: e,
                                                };
                                                let _ = incoming_tx.send(Some(Err(err)));
                                                return;
                                            },
                                        };
                                        let connection_id = match tcp_stream.read_u64::<BigEndian>() {
                                            Ok(connection_id) => connection_id,
                                            Err(e) => {
                                                let err = ListenerAcceptError::TcpRead {
                                                    local_addr: local_addr,
                                                    peer_addr: peer_addr,
                                                    err: e,
                                                };
                                                let _ = incoming_tx.send(Some(Err(err)));
                                                return;
                                            },
                                        };
                                        {
                                            let mut connection_id_filter = unwrap_result!(connection_id_filter.lock());
                                            match connection_id_filter.entry(connection_id) {
                                                lru_time_cache::Entry::Vacant(ve) => {
                                                    let _ = ve.insert(());
                                                },
                                                lru_time_cache::Entry::Occupied(..) => {
                                                    return;
                                                },
                                            };
                                        };
                                        let sender = {
                                            let mut expected_peers_tx = unwrap_result!(expected_peers_tx.lock());
                                            expected_peers_tx.remove(&connection_id)
                                        };
                                        match tcp_stream.write_u64::<BigEndian>(connection_id) {
                                            Ok(()) => (),
                                            Err(e) => {
                                                let err = ListenerAcceptError::TcpWrite {
                                                    local_addr: local_addr,
                                                    peer_addr: peer_addr,
                                                    err: e,
                                                };
                                                let _ = incoming_tx.send(Some(Err(err)));
                                                return;
                                            },
                                        }
                                        match tcp_stream.set_read_timeout(None) {
                                            Ok(()) => (),
                                            Err(e) => {
                                                let err = ListenerAcceptError::TcpSetTimeout {
                                                    local_addr: local_addr,
                                                    peer_addr: peer_addr,
                                                    err: e,
                                                };
                                                let _ = incoming_tx.send(Some(Err(err)));
                                                return;
                                            },
                                        };
                                        let stream = match Stream::from_tcp_stream(tcp_stream, connection_id) {
                                            Ok(stream) => stream,
                                            Err(e) => {
                                                let err = ListenerAcceptError::TcpStreamize {
                                                    local_addr: local_addr,
                                                    peer_addr: peer_addr,
                                                    err: e,
                                                };
                                                let _ = incoming_tx.send(Some(Err(err)));
                                                return;
                                            },
                                        };
                                        match sender {
                                            Some(sender) => {
                                                // This peer was expected from a rendezvous
                                                // connect.
                                                let _ = sender.send(stream);
                                            },
                                            None => {
                                                // An unknown peer making a direct connection.
                                                let _ = incoming_tx.send(Some(Ok(stream)));
                                            }
                                        };
                                    });
                                };
                            });

                            let single_listener = SingleListener {
                                stop_flag: stop_flag,
                                external_endpoints: external_endpoints,
                                local_endpoint: local_endpoint,
                                _listener_thread: RaiiThreadJoiner::new(listener_thread),
                            };
                            let _ = results_tx.send(WOk((local_endpoint, single_listener), warnings));
                        });
                    },
                    ListenEndpoint::Utp(_) => unimplemented!(),
                }
            }
        });
        drop(results_tx);

        let ret = results_rx.into_iter().map(|res| res.map(|(local_endpoint, single_listener)| {
            let mut single_listeners = unwrap_result!(self.single_listeners.write());
            let _ = single_listeners.insert(local_endpoint, single_listener);
            local_endpoint
        })).collect();

        ret
    }

    /*
                    // This is to help with some particularly nasty routers (such as @andreas')
                    // that won't map a port correctly even if port forwarding is set up. They
                    // might be configured to forward external port 1234 to internal port 1234 but
                    // an outgoing connection from port 1234 still won't appear from external port
                    // 1234, making external mapper servers useless. The downside of this hack is
                    // it creates a lot of spurious fake endpoints.
                    // TODO(canndrew): This hack should be moved into crust and use the
                    // add_endpoint method. Remove this completely once we have the ability to
                    // manually specify endpoints in the configuration file.
                    for i in 0..addrs.len() {
                        let ip = addrs[i].ip();
                        let addr = SocketAddr(net::SocketAddr::new(ip, actual_port));
                        if !addrs.contains(&addr) {
                            addrs.push(addr);
                        }
                    }
    */

    /// Register an external endpoint with the `Listener`. This is for informing the `Listener`
    /// about endpoints that it could not discover itself using the `MappingContext`, such as
    /// manually configured external ports on a router.
    pub fn add_external_endpoints<E>(&self, listen_endpoint: ListenEndpoint, endpoints: E)
            -> Result<(), ListenerAddExternalEndpointsError<E::Err>>
        where E: ToEndpoints
    {
        let mut parsed_endpoints = Vec::new();
        for endpoint_res in endpoints.to_endpoints() {
            match endpoint_res {
                Ok(endpoint) => parsed_endpoints.push(endpoint),
                Err(e) => return Err(ListenerAddExternalEndpointsError::ParseEndpoint(e)),
            }
        };

        let mut single_listeners = unwrap_result!(self.single_listeners.write());
        match single_listeners.get_mut(&listen_endpoint) {
            Some(single_listener) => {
                single_listener.external_endpoints.extend(parsed_endpoints);
            },
            None => {
                return Err(ListenerAddExternalEndpointsError::UnknownListenEndpoint);
            },
        }
        Ok(())
    }

    /// Retrieve a list of all our known external endpoints.
    pub fn external_endpoints(&self) -> Vec<Endpoint> {
        let mut ret = Vec::new();
        let single_listeners = unwrap_result!(self.single_listeners.read());
        for single_listener in single_listeners.values() {
            ret.extend(single_listener.external_endpoints.iter());
        }
        ret
    }

    /// Cause any concurrent call to `Listener::accept` to unblock and return `None`
    pub fn stop(&self) {
        let incoming_tx = unwrap_result!(self.incoming_tx.lock());
        let _ = incoming_tx.send(None);
    }

    /// Block until there is a new incoming connection or `Listener::stop` is called.
    pub fn accept(&self) -> Option<Result<Stream, ListenerAcceptError>> {
        let incoming_rx = unwrap_result!(self.incoming_rx.lock());
        // Cannot panic as we are holding a copy of incoming_tx in self
        unwrap_result!(incoming_rx.recv())
    }

    /// Generate rendezvous info that can be used to connect to this listener set. The returned
    /// `PrivRendezvousInfo` should be used in a later call to `Listener::rendezvous_connect`. The
    /// `PubRendezvousInfo` should be swapped with that of the remote peer. The
    /// `StreamGenRendezvousInfoDiagnostics` contains information that may be useful in diagnosing
    /// problems with using this rendezvous info.
    pub fn gen_rendezvous_info(&self, deadline: Instant)
            -> (PrivRendezvousInfo, PubRendezvousInfo, StreamGenRendezvousInfoDiagnostics)
    {
        let (priv_info, mut pub_info, diags) = Stream::gen_rendezvous_info(
                self.mapping_context.as_ref(),
                deadline
        );
        pub_info.static_endpoints.extend(self.external_endpoints());

        let (stream_tx, stream_rx) = mpsc::channel();
        {
            let mut expected_peers_tx = unwrap_result!(self.expected_peers_tx.lock());
            let _ = expected_peers_tx.insert(pub_info.connection_id_half, stream_tx);
        }
        {
            let mut expected_peers_rx = unwrap_result!(self.expected_peers_rx.lock());
            let _ = expected_peers_rx.insert(pub_info.connection_id_half, stream_rx);
        }

        (priv_info, pub_info, diags)
    }

    /// Perform a rendezvous connection, making use of the listeners in this listener set. This
    /// function should be called by both peers wishing to connect. Both peers will attempt to
    /// connect to each others listeners while also attempting to make nat-traversed connections.
    pub fn rendezvous_connect(&self,
                              our_priv_info: PrivRendezvousInfo,
                              their_pub_info: PubRendezvousInfo,
                              deadline: Instant)
            -> WResult<Stream, StreamRendezvousConnectWarning, StreamRendezvousConnectError>
    {
        let our_connection_id_half = our_priv_info.connection_id_half;
        let their_connection_id_half = their_pub_info.connection_id_half;

        // Get the receiver that incoming direct connects will arrive on.
        let stream_rx = {
            let mut expected_peers_rx = unwrap_result!(self.expected_peers_rx.lock());
            match expected_peers_rx.remove(&our_connection_id_half) {
                Some(stream_rx) => stream_rx,
                None => return WErr(StreamRendezvousConnectError::Expired),
            }
        };

        // Early exit if we've already received a connection on a listener for this rendezvous
        // connect.
        if let Ok(stream) = stream_rx.try_recv() {
            return WOk(stream, Vec::new());
        }

        // Attempt a Stream::rendezvous connect in parallel with waiting for an incoming stream on
        // a listener. 
        let (rendezvous_result_tx, rendezvous_result_rx) = mpsc::channel();
        let _ = thread!("ListenerSet::rendezvous_connect stream", move || {
            let result = Stream::rendezvous_connect(our_priv_info, their_pub_info, deadline);
            let _ = rendezvous_result_tx.send(result);
        });

        let (accept_result_tx, accept_result_rx) = mpsc::channel();
        let accept_result_tx_clone = accept_result_tx.clone();
        let _ = thread!("ListenerSet::rendezovus_connect accept", move || {
            let accept_result_tx = accept_result_tx_clone;
            let stream_opt = stream_rx.recv().ok();
            let _ = accept_result_tx.send(stream_opt);
        });

        let timeout_thread = thread!("ListenerSet::rendezvous_connect timeout", move || {
            let now = Instant::now();
            if deadline > now {
                let timeout = deadline - now;
                thread::park_timeout(timeout);
            }
            let _ = accept_result_tx.send(None);
        });

        // To avoid the race condition where different sides keep different successful connections
        // we prioritise based on our connection_id halves. If we have the lower connection_id half
        // then we prioritise accepted connections. Otherwise we prioritise initiated connections.

        if our_connection_id_half < their_connection_id_half {
            // Cannot panic as we always send on accept_result_tx before dropping it.
            if let Some(stream) = unwrap_result!(accept_result_rx.recv()) {
                timeout_thread.thread().unpark();
                return WOk(stream, Vec::new());
            };

            // Can only panic if the Stream::rendezvous_connect thread panicked;
            let ret = unwrap_result!(rendezvous_result_rx.recv());
            timeout_thread.thread().unpark();
            ret
        }
        else {
            // Can only panic if the Stream::rendezvous_connect thread panicked;
            let err = match unwrap_result!(rendezvous_result_rx.recv()) {
                WOk(stream, ws) => {
                    timeout_thread.thread().unpark();
                    return WOk(stream, ws);
                },
                WErr(err) => err,
            };

            // Cannot panic as we always send on accept_result_tx before dropping it.
            if let Some(stream) = unwrap_result!(accept_result_rx.recv()) {
                timeout_thread.thread().unpark();
                return WOk(stream, Vec::new());
            };

            timeout_thread.thread().unpark();
            WErr(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Instant, Duration};
    use std::net;
    use std::sync::Arc;

    use nat_traversal::MappingContext;
    use maidsafe_utilities;
    use crossbeam;
    use socket_addr::SocketAddr;

    use socket_utils;
    use endpoint::Endpoint;
    use listen_endpoint::ListenEndpoint;
    use listener::Listener;
    use stream::Stream;
    use test_utils::{timebomb, check_stream, bounce_stream};

    #[test]
    fn accept_from_two_listeners() {
        let _ = maidsafe_utilities::log::init(true);

        timebomb(Duration::from_secs(8), || {
            let mc = Arc::new(unwrap_result!(MappingContext::new().result_log()));
            let listener = Listener::new(mc);

            let deadline = Instant::now() + Duration::from_secs(3);
            for r in listener.bind("tcp-listen://0.0.0.0:0", deadline) {
                let listen_endpoint = unwrap_result!(r.result_log());
                match listen_endpoint {
                    ListenEndpoint::Tcp(SocketAddr(net::SocketAddr::V4(addr_v4))) |
                    ListenEndpoint::Utp(SocketAddr(net::SocketAddr::V4(addr_v4))) => {
                        assert!(addr_v4.port() != 0);
                    },
                    ListenEndpoint::Tcp(SocketAddr(net::SocketAddr::V6(addr_v6))) |
                    ListenEndpoint::Utp(SocketAddr(net::SocketAddr::V6(addr_v6))) => {
                        assert!(addr_v6.port() != 0);
                    },
                }
            }
            let endpoints_0: Vec<Endpoint> = listener.external_endpoints();

            let deadline = Instant::now() + Duration::from_secs(3);
            for r in listener.bind("tcp-listen://0.0.0.0:0", deadline) {
                let listen_endpoint = unwrap_result!(r.result_log());
                match listen_endpoint {
                    ListenEndpoint::Tcp(SocketAddr(net::SocketAddr::V4(addr_v4))) |
                    ListenEndpoint::Utp(SocketAddr(net::SocketAddr::V4(addr_v4))) => {
                        assert!(addr_v4.port() != 0);
                    },
                    ListenEndpoint::Tcp(SocketAddr(net::SocketAddr::V6(addr_v6))) |
                    ListenEndpoint::Utp(SocketAddr(net::SocketAddr::V6(addr_v6))) => {
                        assert!(addr_v6.port() != 0);
                    },
                }
            }
            let endpoints_1: Vec<Endpoint> = listener.external_endpoints()
                                                     .into_iter()
                                                     .filter(|e| !endpoints_0.contains(e))
                                                     .collect();
            assert!(endpoints_0.len() >= 1);
            for endpoint in &endpoints_0 {
                match *endpoint {
                    Endpoint::Tcp(SocketAddr(net::SocketAddr::V4(addr_v4))) |
                    Endpoint::Utp(SocketAddr(net::SocketAddr::V4(addr_v4))) => {
                        assert!(!socket_utils::ipv4_addr_is_unspecified(addr_v4.ip()));
                        assert!(addr_v4.port() != 0);
                    },
                    Endpoint::Tcp(SocketAddr(net::SocketAddr::V6(addr_v6))) |
                    Endpoint::Utp(SocketAddr(net::SocketAddr::V6(addr_v6))) => {
                        assert!(!addr_v6.ip().is_unspecified());
                        assert!(addr_v6.port() != 0);
                    },
                }
            }

            assert!(endpoints_1.len() >= 1);
            for endpoint in &endpoints_1 {
                match *endpoint {
                    Endpoint::Tcp(SocketAddr(net::SocketAddr::V4(addr_v4))) |
                    Endpoint::Utp(SocketAddr(net::SocketAddr::V4(addr_v4))) => {
                        assert!(!socket_utils::ipv4_addr_is_unspecified(addr_v4.ip()));
                        assert!(addr_v4.port() != 0);
                    },
                    Endpoint::Tcp(SocketAddr(net::SocketAddr::V6(addr_v6))) |
                    Endpoint::Utp(SocketAddr(net::SocketAddr::V6(addr_v6))) => {
                        assert!(!addr_v6.ip().is_unspecified());
                        assert!(addr_v6.port() != 0);
                    },
                }
            }

            crossbeam::scope(|scope| {
                let _ = scope.spawn(|| {
                    trace!("Accepting stream 0");
                    let mut stream_0 = unwrap_result!(unwrap_option!(listener.accept(), "expected stream"));
                    bounce_stream(&mut stream_0);

                    trace!("Accepting stream 1");
                    let mut stream_1 = unwrap_result!(unwrap_option!(listener.accept(), "expected stream"));
                    bounce_stream(&mut stream_1);

                    trace!("Waiting for listener to stop");
                    match listener.accept() {
                        Some(..) => panic!("Unexpected result!"),
                        None => (),
                    };

                    trace!("listener stopped");
                });
                
                trace!("Connecting stream 0");
                let deadline = Instant::now() + Duration::from_millis(100);
                let mut stream_0 = unwrap_result!(Stream::direct_connect(&endpoints_0[..], deadline));
                check_stream(&mut stream_0);

                trace!("Connecting stream 1");
                let deadline = Instant::now() + Duration::from_millis(100);
                let mut stream_1 = unwrap_result!(Stream::direct_connect(&endpoints_1[..], deadline));
                check_stream(&mut stream_1);

                trace!("Stopping listener");
                listener.stop();

                trace!("Told listener to stop");
            });
        })
    }

    #[test]
    fn rendezvous_connect_to_listener() {
        let _ = maidsafe_utilities::log::init(true);

        timebomb(Duration::from_secs(20), || {
            let mc = Arc::new(unwrap_result!(MappingContext::new().result_log()));

            let deadline = Instant::now() + Duration::from_secs(3);

            let listener = Listener::new(mc.clone());
            for r in listener.bind("tcp-listen://0.0.0.0:0", deadline) {
                let listen_endpoint = unwrap_result!(r.result_log());
                match listen_endpoint {
                    ListenEndpoint::Tcp(SocketAddr(net::SocketAddr::V4(addr_v4))) |
                    ListenEndpoint::Utp(SocketAddr(net::SocketAddr::V4(addr_v4))) => {
                        assert!(addr_v4.port() != 0);
                    },
                    ListenEndpoint::Tcp(SocketAddr(net::SocketAddr::V6(addr_v6))) |
                    ListenEndpoint::Utp(SocketAddr(net::SocketAddr::V6(addr_v6))) => {
                        assert!(addr_v6.port() != 0);
                    },
                }
            }
        
            let deadline = Instant::now() + Duration::from_secs(3);
            let (mut priv_info_0, pub_info_0, diags) = listener.gen_rendezvous_info(deadline);
            info!("info_0: {}", diags);

            let deadline = Instant::now() + Duration::from_secs(3);
            let (priv_info_1, pub_info_1, diags) = Stream::gen_rendezvous_info(&mc, deadline);
            info!("info_1: {}", diags);

            priv_info_0.priv_tcp_info = None;
            priv_info_0.priv_udp_info = None;

            let deadline = Instant::now() + Duration::from_secs(3);
            let _ = thread!("listener_set_rendezvous_connect", move || {
                let mut stream = unwrap_result!(Stream::rendezvous_connect(priv_info_1, pub_info_0, deadline)
                                                       .result_log());
                bounce_stream(&mut stream);
            });

            trace!("rendezvous_connect_to_listener calling rendezvous connect");
            let mut stream = unwrap_result!(listener.rendezvous_connect(priv_info_0, pub_info_1, deadline)
                                                    .result_log());
            check_stream(&mut stream);

            trace!("rendezvous_connect_to_listener exiting closure");
        })
    }

    #[test]
    fn rendezvous_connect_two_listeners() {
        const NUM_ENDPOINTS: u32 = 5;
        const NUM_STREAMS: u32 = 10;

        let _ = maidsafe_utilities::log::init(true);

        timebomb(Duration::from_secs(300), || {
            let mc = Arc::new(unwrap_result!(MappingContext::new().result_log()));

            let listener_0 = Listener::new(mc.clone());

            for _ in 0..NUM_ENDPOINTS {
                let deadline = Instant::now() + Duration::from_secs(4);
                let _ = listener_0.bind("tcp-listen://0.0.0.0:0", deadline);
            }

            let listener_1 = Listener::new(mc);

            for _ in 0..NUM_ENDPOINTS {
                let deadline = Instant::now() + Duration::from_secs(4);
                let _ = listener_1.bind("tcp-listen://0.0.0.0:0", deadline);
            }

            trace!("\n\n\n\t\t\tStarting direct tests\n\n\n");

            // Check direct connects
            for _ in 0..NUM_STREAMS {
                let deadline = Instant::now() + Duration::from_secs(4);
                let (mut priv_info_0, mut pub_info_0, diags_0) = listener_0.gen_rendezvous_info(deadline);
                info!("diags_0: {}", diags_0);
                let deadline = Instant::now() + Duration::from_secs(4);
                let (mut priv_info_1, mut pub_info_1, diags_1) = listener_1.gen_rendezvous_info(deadline);
                info!("diags_1: {}", diags_1);
                priv_info_0.priv_tcp_info = None;
                priv_info_0.priv_udp_info = None;
                pub_info_0.pub_tcp_info = None;
                pub_info_0.pub_udp_info = None;
                priv_info_1.priv_tcp_info = None;
                priv_info_1.priv_udp_info = None;
                pub_info_1.pub_tcp_info = None;
                pub_info_1.pub_udp_info = None;
                let deadline = Instant::now() + Duration::from_secs(4);

                crossbeam::scope(|scope| {
                    let _ = scope.spawn(|| {
                        let mut stream = unwrap_result!(listener_0.rendezvous_connect(priv_info_0, pub_info_1, deadline).result_log());
                        bounce_stream(&mut stream);
                    });
                    let _ = scope.spawn(|| {
                        let mut stream = unwrap_result!(listener_1.rendezvous_connect(priv_info_1, pub_info_0, deadline).result_log());
                        check_stream(&mut stream);
                    });
                });
            }

            trace!("\n\n\n\t\t\tStarting TCP tests\n\n\n");

            // Check tcp connects
            for _ in 0..NUM_STREAMS {
                let deadline = Instant::now() + Duration::from_secs(4);
                let (mut priv_info_0, mut pub_info_0, diags_0) = listener_0.gen_rendezvous_info(deadline);
                info!("diags_0: {}", diags_0);
                let deadline = Instant::now() + Duration::from_secs(4);
                let (mut priv_info_1, mut pub_info_1, diags_1) = listener_1.gen_rendezvous_info(deadline);
                info!("diags_1: {}", diags_1);
                priv_info_0.priv_udp_info = None;
                pub_info_0.pub_udp_info = None;
                pub_info_0.static_endpoints = Vec::new();
                priv_info_1.priv_udp_info = None;
                pub_info_1.pub_udp_info = None;
                pub_info_1.static_endpoints = Vec::new();
                let deadline = Instant::now() + Duration::from_secs(4);
                
                crossbeam::scope(|scope| {
                    let _ = scope.spawn(|| {
                        let mut stream = unwrap_result!(listener_0.rendezvous_connect(priv_info_0, pub_info_1, deadline).result_log());
                        bounce_stream(&mut stream);
                    });
                    let _ = scope.spawn(|| {
                        let mut stream = unwrap_result!(listener_1.rendezvous_connect(priv_info_1, pub_info_0, deadline).result_log());
                        check_stream(&mut stream);
                    });
                });
            }
        });
    }
}

