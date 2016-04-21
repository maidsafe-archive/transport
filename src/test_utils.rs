use std::time::Duration;
use std::io::{Read, Write};

use crossbeam;
use rand;

use stream::Stream;

pub fn timebomb<R, F>(dur: Duration, f: F) -> R
    where R: Send,
          F: Send + FnOnce() -> R
{
    use std::thread;
    use std::sync::mpsc;

    use void::Void;

    crossbeam::scope(|scope| {
        let thread_handle = thread::current();
        let (done_tx, done_rx) = mpsc::channel::<Void>();
        let jh = scope.spawn(move || {
            let ret = f();
            drop(done_tx);
            thread_handle.unpark();
            ret
        });
        thread::park_timeout(dur);
        match done_rx.try_recv() {
            Ok(x) => match x {},
            Err(mpsc::TryRecvError::Empty) => panic!("Timed out!"),
            Err(mpsc::TryRecvError::Disconnected) => jh.join(),
        }
    })
}

pub fn check_stream(stream: &mut Stream) {
    let send_data: [u8; 8] = rand::random();
    unwrap_result!(stream.write_all(&send_data[..]));

    let mut recv_data = [0u8; 8];
    unwrap_result!(stream.read_exact(&mut recv_data[..]));
    assert_eq!(send_data, recv_data);
}

pub fn bounce_stream(stream: &mut Stream) {
    let mut data = [0u8; 8];
    unwrap_result!(stream.read_exact(&mut data[..]));
    unwrap_result!(stream.write_all(&data[..]));
}

