use std::{io::ErrorKind, pin::Pin, task::Poll};

use futures::ready;
use h2::{Reason, RecvStream, SendStream};
use hyper::body::Bytes;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc::{self, error::TrySendError},
};

pub struct TunnelStream {
    pub recv: RecvStream,
    pub send: SendStream<Bytes>,
}

impl TunnelStream {
    fn send_data(&mut self, buf: &[u8], end_of_stream: bool) -> std::result::Result<(), h2::Error> {
        let bytes = Bytes::copy_from_slice(buf);
        self.send.send_data(bytes, end_of_stream)
    }

    fn handle_io_error(e: h2::Error) -> std::io::Error {
        if e.is_io() {
            e.into_io().unwrap()
        } else {
            std::io::Error::new(std::io::ErrorKind::Other, e)
        }
    }
}

impl AsyncRead for TunnelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            match ready!(self.recv.poll_data(cx)) {
                Some(Ok(bytes)) if bytes.is_empty() && !self.recv.is_end_stream() => continue,
                Some(Ok(bytes)) => {
                    let _ = self.recv.flow_control().release_capacity(bytes.len());
                    buf.put_slice(&bytes);
                    return Poll::Ready(Ok(()));
                }
                Some(Err(e)) => {
                    let err = match e.reason() {
                        Some(Reason::NO_ERROR) | Some(Reason::CANCEL) => {
                            return Poll::Ready(Ok(()));
                        }
                        Some(Reason::STREAM_CLOSED) => {
                            std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)
                        }
                        _ => TunnelStream::handle_io_error(e),
                    };

                    return Poll::Ready(Err(err));
                }
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        self.send.reserve_capacity(buf.len());

        let cnt = match ready!(self.send.poll_capacity(cx)) {
            Some(Ok(cnt)) => match self.send_data(&buf[..cnt], false) {
                _ => Some(cnt),
            },
            Some(Err(_)) => None,
            None => Some(0),
        };

        if let Some(cnt) = cnt {
            return Poll::Ready(Ok(cnt));
        }

        let err = match ready!(self.send.poll_reset(cx)) {
            Ok(Reason::NO_ERROR) | Ok(Reason::CANCEL) | Ok(Reason::STREAM_CLOSED) => {
                ErrorKind::BrokenPipe.into()
            }
            Ok(reason) => TunnelStream::handle_io_error(reason.into()),
            Err(e) => TunnelStream::handle_io_error(e),
        };

        Poll::Ready(Err(err))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        let res = self.send_data(&[], true);

        if res.is_ok() {
            return Poll::Ready(Ok(()));
        }

        let err = match ready!(self.send.poll_reset(cx)) {
            Ok(Reason::NO_ERROR) => return Poll::Ready(Ok(())),
            Ok(Reason::CANCEL) | Ok(Reason::STREAM_CLOSED) => {
                return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
            }
            Ok(reason) => TunnelStream::handle_io_error(reason.into()),
            Err(e) => TunnelStream::handle_io_error(e),
        };

        Poll::Ready(Err(err))
    }
}

pub struct ChannelStream<T> {
    pub recv: mpsc::Receiver<T>,
    pub send: mpsc::Sender<T>,
}

impl<T> ChannelStream<T> {}

impl<T: Into<Bytes>> AsyncRead for ChannelStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            match ready!(self.recv.poll_recv(cx)) {
                Some(item) => {
                    let bytes = item.into();
                    buf.put_slice(&bytes);
                    return Poll::Ready(Ok(()));
                }
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl<T: From<Bytes>> AsyncWrite for ChannelStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let bytes = Bytes::copy_from_slice(buf);

        match self.send.try_send(bytes.into()) {
            Ok(_) => Poll::Ready(Ok(buf.len())),
            Err(e) => match e {
                TrySendError::Full(_) => Poll::Ready(Ok(0)),
                TrySendError::Closed(_) => Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "channel closed",
                ))),
            },
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}
