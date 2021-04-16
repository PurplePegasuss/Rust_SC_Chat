use native_tls::{Identity, TlsAcceptor, TlsStream};
use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::collections::HashMap;

type Shared<T> = Arc<Mutex<T>>;

//Structure used for describing a single client (+ login as a key)
pub struct Client {
    password: String,
    username: String,
}

//native functions for authorization system (not used yet)
impl Client {
    pub fn change_password(&mut self, new_password: String) {
        self.password = new_password;
    }

    pub fn change_username(&mut self, new_username: String) {
        self.username = new_username;
    }
}

fn main() {
    //Hashmap which will store login/password/username for all users
    let credentials_db: Shared<HashMap<String, Client>> = Arc::new(
        Mutex::new(
            HashMap::new()
        )
    );

    let mut file = File::open("identity.pfx").unwrap();

    //Reading the identity certificate used for TLS connection
    let mut identity = vec![];
    file.read_to_end(&mut identity).unwrap();

    //Unfolding unique certificate for each client machine as a PK12 format
    let identity = Identity::from_pkcs12(&identity, "localhost").unwrap();

    //TLS acceptor which uses a certificate to provide security of data
    let acceptor = TlsAcceptor::new(identity).unwrap();
    let acceptor = Arc::new(acceptor);

    // TCP listener which waits for a new connections in a passive mode
    let listener = TcpListener::bind("0.0.0.0:8080").unwrap();

    //Vector of all current streams used by different clients
    let all_sockets: Shared<Vec<Shared<TlsStream<TcpStream>>>> = Arc::new(
        Mutex::new(
            Vec::new()
        )
    );

    // Establishing connection for each client in listening queue
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let acceptor = acceptor.clone();
                let all_sockets = all_sockets.clone();
                let credentials_db = credentials_db.clone();
                //Creating a new thread for handling different streams
                thread::spawn(move || {
                    let stream = acceptor.accept(stream).unwrap();
                    let stream = Arc::new(Mutex::new(stream));
                    handle_client(stream, all_sockets, credentials_db);
                });
            }
            Err(e) => {
                println!("Connection failed!: {}", e);
            }
        }
    }
}

//Function which performs basic communicative operations with the client
fn handle_client(
    stream: Shared<TlsStream<TcpStream>>,
    all_sockets: Shared<Vec<Shared<TlsStream<TcpStream>>>>,
    credentials_db: Shared<HashMap<String, Client>>)
{
    let mut authentication_incorrect: bool = true;
    while authentication_incorrect {
        println!("New client {}. Sending a request to provide credentials...",
                 stream.lock().unwrap().get_ref().peer_addr().unwrap());
        all_sockets.lock().unwrap().push(stream.clone());

        let mut buf = vec!();

        // Read login/register credentials
        read_until_2rn(&mut stream.lock().unwrap(), &mut buf);
        let ind_cred_raw = String::from_utf8_lossy(&buf);

        // 2 or 3 sized vector (depending on login or registration)
        let ind_credentials: Vec<&str> = ind_cred_raw.split("/").collect();

        // Login section
        if ind_credentials.len() == 2 {
            //Check if the user exists in our database
            if credentials_db.lock().unwrap().contains_key(ind_credentials[0]) {
                //Check if the password from the database matches password entered by user
                if credentials_db.lock().unwrap().get(ind_credentials[0]).unwrap().password == ind_credentials[1].trim_end_matches("\n\r\n\r\n") {
                    //if passwords match, we send signal to a client to stop entering credentials
                    println!("Login successful.");
                    stream.lock().unwrap().write(b"correct\r\n\r\n").unwrap();
                    authentication_incorrect = false;
                }
                else {
                    //if passwords do not match, we send signal to continue entering credentials
                    println!("Invalid password.");
                    stream.lock().unwrap().write(b"Invalid password.\r\n\r\n").unwrap();
                }
            } else {
                //if there is no such user in database, we send signal to continue entering credentials
                println!("User with such login does not exist.");
                stream.lock().unwrap().write(b"User with such login does not exist.\r\n\r\n").unwrap();
            }
        }
        // Registration section
        else if ind_credentials.len() == 3 {
            //Check if user with such login already exists
            if !credentials_db.lock().unwrap().contains_key(ind_credentials[0]){
                credentials_db.lock().unwrap().insert(ind_credentials[0].to_string(),
                                                      Client {
                                                          password:
                                                          ind_credentials[1].to_string(),
                                                          username:
                                                          ind_credentials[2].trim_end_matches("\n\r\n\r\n").to_string()
                                                      });
                stream.lock().unwrap().write(b"correct\r\n\r\n").unwrap();
                println!("Registration successful.\n");
                authentication_incorrect = false;
            }else{
                //if there is such name in database, we can't create additional account
                println!("User with such login exists.");
                stream.lock().unwrap().write(b"User with such login exists.\r\n\r\n").unwrap();
            }

        } else {
            // Error handling for cases with format different from */* or */*/*
            println!("Invalid format");
            stream.lock().unwrap().write(b"Invalid format!\r\n\r\n").unwrap();
        }
        buf.clear();
    }
    // End connection after serving the client
    stream.lock().unwrap().shutdown().unwrap();
}

// Reads from the stream until it receives '\r\n\r\n' sequence
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
                } else if inner_buf[0] == b'\n' && was_r {
                    rn_count += 1;
                    was_r = false;
                } else {
                    rn_count = 0;
                    was_r = false;
                }
            }
            true
        }
        Err(e) => {
            println!("Error while receiving message: {}", e);
            false
        }
    } {}
}
