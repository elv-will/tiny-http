use std::io::Result as IoResult;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};

#[cfg(feature = "mbtls")]
use mbedtls::ssl::{Config, Context};
#[cfg(feature = "ssl")]
use openssl::ssl::SslStream;
#[cfg(any(feature = "mbtls", feature = "ssl"))]
use std::sync::{Arc, Mutex};

pub struct RefinedTcpStream {
    stream: Stream,
    close_read: bool,
    close_write: bool,
}

#[cfg(feature = "mbtls")]
pub struct MbedTlsStream {
    pub ctx: Context,
    pub peer_addr: SocketAddr,
}

#[cfg(feature = "mbtls")]
impl MbedTlsStream {
    pub fn new(config: Arc<Config>, peer_addr: SocketAddr) -> MbedTlsStream {
        MbedTlsStream {
            ctx: mbedtls::ssl::Context::new(config),
            peer_addr,
        }
    }
}

pub enum Stream {
    Http(TcpStream),
    #[cfg(feature = "ssl")]
    Https(Arc<Mutex<SslStream<TcpStream>>>),
    #[cfg(feature = "mbtls")]
    MbedTls(Arc<Mutex<MbedTlsStream>>),
}

impl From<TcpStream> for Stream {
    #[inline]
    fn from(stream: TcpStream) -> Stream {
        Stream::Http(stream)
    }
}

#[cfg(feature = "ssl")]
impl From<SslStream<TcpStream>> for Stream {
    #[inline]
    fn from(stream: SslStream<TcpStream>) -> Stream {
        Stream::Https(Arc::new(Mutex::new(stream)))
    }
}

#[cfg(feature = "mbedtls")]
impl From<MbedTlsStream> for Stream {
    fn from(ctx: MbedTlsStream) -> Self {
        Stream::MbedTls(Arc::new(Mutex::new(ctx)))
    }
}

impl RefinedTcpStream {
    pub fn new<S>(stream: S) -> (RefinedTcpStream, RefinedTcpStream)
    where
        S: Into<Stream>,
    {
        let stream = stream.into();

        let read = match stream {
            Stream::Http(ref stream) => Stream::Http(stream.try_clone().unwrap()),
            #[cfg(feature = "ssl")]
            Stream::Https(ref stream) => Stream::Https(stream.clone()),
            #[cfg(feature = "mbtls")]
            Stream::MbedTls(ref stream) => Stream::MbedTls(stream.clone()),
        };

        let read = RefinedTcpStream {
            stream: read,
            close_read: true,
            close_write: false,
        };

        let write = RefinedTcpStream {
            stream,
            close_read: false,
            close_write: true,
        };

        (read, write)
    }

    /// Returns true if this struct wraps arounds a secure connection.
    #[inline]
    pub fn secure(&self) -> bool {
        match self.stream {
            Stream::Http(_) => false,
            #[cfg(feature = "ssl")]
            Stream::Https(_) => true,
            #[cfg(feature = "mbtls")]
            Stream::MbedTls(_) => true,
        }
    }

    pub fn peer_addr(&mut self) -> IoResult<SocketAddr> {
        match self.stream {
            Stream::Http(ref mut stream) => stream.peer_addr(),
            #[cfg(feature = "ssl")]
            Stream::Https(ref mut stream) => stream.lock().unwrap().get_ref().peer_addr(),
            #[cfg(feature = "mbtls")]
            Stream::MbedTls(ref mut stream) => Ok(stream.lock().unwrap().peer_addr),
        }
    }
}

impl Drop for RefinedTcpStream {
    fn drop(&mut self) {
        if self.close_read {
            match self.stream {
                // ignoring outcome
                Stream::Http(ref mut stream) => stream.shutdown(Shutdown::Read).ok(),
                #[cfg(feature = "ssl")]
                Stream::Https(ref mut stream) => stream
                    .lock()
                    .unwrap()
                    .get_mut()
                    .shutdown(Shutdown::Read)
                    .ok(),
                #[cfg(feature = "mbtls")]
                Stream::MbedTls(_) => Some(()), // Should handle in the context object
            };
        }

        if self.close_write {
            match self.stream {
                // ignoring outcome
                Stream::Http(ref mut stream) => stream.shutdown(Shutdown::Write).ok(),
                #[cfg(feature = "ssl")]
                Stream::Https(ref mut stream) => stream
                    .lock()
                    .unwrap()
                    .get_mut()
                    .shutdown(Shutdown::Write)
                    .ok(),
                #[cfg(feature = "mbtls")]
                Stream::MbedTls(_) => Some(()),
            };
        }
    }
}

impl Read for RefinedTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        match self.stream {
            Stream::Http(ref mut stream) => stream.read(buf),
            #[cfg(feature = "ssl")]
            Stream::Https(ref mut stream) => stream.lock().unwrap().read(buf),
            #[cfg(feature = "mbtls")]
            Stream::MbedTls(ref mut stream) => stream.lock().unwrap().ctx.read(buf),
        }
    }
}

impl Write for RefinedTcpStream {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        match self.stream {
            Stream::Http(ref mut stream) => stream.write(buf),
            #[cfg(feature = "ssl")]
            Stream::Https(ref mut stream) => stream.lock().unwrap().write(buf),
            #[cfg(feature = "mbtls")]
            Stream::MbedTls(ref mut stream) => stream.lock().unwrap().ctx.write(buf),
        }
    }

    fn flush(&mut self) -> IoResult<()> {
        match self.stream {
            Stream::Http(ref mut stream) => stream.flush(),
            #[cfg(feature = "ssl")]
            Stream::Https(ref mut stream) => stream.lock().unwrap().flush(),
            #[cfg(feature = "mbtls")]
            Stream::MbedTls(ref mut stream) => stream.lock().unwrap().ctx.flush(),
        }
    }
}
