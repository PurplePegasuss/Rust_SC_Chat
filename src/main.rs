use native_tls::{Identity, TlsAcceptor, TlsStream};
use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

type Shared<T> = Arc<Mutex<T>>;

fn main() {
    let mut file = File::open("identity.pfx").unwrap();
    let mut identity = vec![];
    file.read_to_end(&mut identity).unwrap();
    let identity = Identity::from_pkcs12(&identity, "localhost").unwrap();

    let acceptor = TlsAcceptor::new(identity).unwrap();
    let acceptor = Arc::new(acceptor);


    let listener = TcpListener::bind("0.0.0.0:8080").unwrap();

    // Reads from the stream until it recieves '\r\n\r\n' sequence
    fn read_until_2rn(stream: &mut TlsStream<TcpStream>, buf: &mut Vec<u8>) {
        let mut inner_buf = [0];
        let mut was_r = false;
        let mut rn_count = 0;
        while rn_count < 2 && match stream.read(&mut inner_buf) {
            Ok(size) => {
                if size == 1 {
                    buf.push(inner_buf[0]);
                    if inner_buf[0] == b'\r' {
                        was_r = true
                    }
                    else if inner_buf[0] == b'\n' && was_r {
                        rn_count += 1;
                        was_r = false;
                    }
                    else {
                        rn_count = 0;
                        was_r = false;
                    }
                }
                true
            },
            Err(e) => {
                println!("Error while recieving message: {}", e);
                false
            }
        } {}
    }

    fn handle_client(
        stream: Shared<TlsStream<TcpStream>>,
        all_sockets: Shared<Vec<Shared<TlsStream<TcpStream>>>>
    ) {
        println!("New client '{}'", stream.lock().unwrap().get_ref().peer_addr().unwrap());
        all_sockets.lock().unwrap().push(stream.clone());

        stream.lock().unwrap().write(b"aboba\r\n\r\n").unwrap();
        let mut buf = vec!();

        // Read 2 messages, to test concurrency
        read_until_2rn(&mut stream.lock().unwrap(), &mut buf);
        println!("Recieved '{}'", String::from_utf8_lossy(&buf));

        buf.clear();

        read_until_2rn(&mut stream.lock().unwrap(), &mut buf);
        println!("Recieved '{}'", String::from_utf8_lossy(&buf));

        println!("Shutting down stream...");

        // End connection after serving the client
        stream.lock().unwrap().shutdown().unwrap();
    }

    let all_sockets:  Shared<Vec<Shared<TlsStream<TcpStream>>>> = Arc::new(
        Mutex::new(
            Vec::new()
        )
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let acceptor = acceptor.clone();
                let all_sockets = all_sockets.clone();
                thread::spawn(move || {
                    let stream = acceptor.accept(stream).unwrap();
                    let stream = Arc::new(Mutex::new(stream));
                    handle_client(stream, all_sockets);
                });
            }
            Err(e) => {
                println!("Connection failed!: {}", e);
            }
        }
    }
}