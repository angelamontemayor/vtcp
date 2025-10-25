#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::socket::tcp::{SocketBuffer, State};
    use crate::socket::Context;
    use crate::wire::{IpRepr, IpProtocol, TcpRepr, TcpSeqNumber, TcpControl, IpAddress, IpEndpoint};

    #[cfg(feature = "proto-ipv4")]
    use crate::wire::{Ipv4Address, Ipv4Repr};

    // =========================================================================================//
    // Constants for testing (matching tcp.rs)
    // =========================================================================================//
    const LOCAL_PORT: u16 = 80;
    const REMOTE_PORT: u16 = 49500;
    const LOCAL_SEQ: TcpSeqNumber = TcpSeqNumber(10000);
    const REMOTE_SEQ: TcpSeqNumber = TcpSeqNumber(50000);

    #[cfg(feature = "proto-ipv4")]
    const LOCAL_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    #[cfg(feature = "proto-ipv4")]
    const REMOTE_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);

    // Template for incoming packets (from remote) - matches SEND_TEMPL in tcp.rs
    const SEND_TEMPL: TcpRepr<'static> = TcpRepr {
        src_port: REMOTE_PORT,
        dst_port: LOCAL_PORT,
        control: TcpControl::None,
        seq_number: TcpSeqNumber(0),
        ack_number: Some(TcpSeqNumber(0)),
        window_len: 256,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };

    #[cfg(feature = "proto-ipv4")]
    const SEND_IP_TEMPL: IpRepr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: REMOTE_ADDR,
        dst_addr: LOCAL_ADDR,
        next_header: IpProtocol::Tcp,
        payload_len: 20,
        hop_limit: 64,
    });

    // =========================================================================================//
    // Helper structures and functions
    // =========================================================================================//

    struct TestSocket {
        socket: Socket<'static>,
        cx: Context,
    }

    fn socket() -> TestSocket {
        socket_with_buffer_sizes(64, 64)
    }

    fn socket_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let (iface, _, _) = crate::tests::setup(crate::phy::Medium::Ip);

        let rx_buffer = SocketBuffer::new(vec![0; rx_len]);
        let tx_buffer = SocketBuffer::new(vec![0; tx_len]);
        let socket = Socket::new(rx_buffer, tx_buffer);

        TestSocket {
            socket,
            cx: iface.inner,
        }
    }

    const TUPLE: Tuple = Tuple {
        local: IpEndpoint {
            addr: IpAddress::Ipv4(LOCAL_ADDR),
            port: LOCAL_PORT,
        },
        remote: IpEndpoint {
            addr: IpAddress::Ipv4(REMOTE_ADDR),
            port: REMOTE_PORT,
        },
    };

    fn socket_syn_received_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let mut s = socket_with_buffer_sizes(tx_len, rx_len);
        s.socket.state.conn_mgmt.tcp_state = State::SynReceived;
        s.socket.state.conn_mgmt.tuple = Some(TUPLE);
        s.socket.state.delivery.remote_seq_no = REMOTE_SEQ + 1;
        s.socket.state.delivery.local_seq_no = LOCAL_SEQ;
        s.socket.state.flow_control.remote_win_len = 256;
        s
    }

    fn socket_syn_received() -> TestSocket {
        socket_syn_received_with_buffer_sizes(64, 64)
    }

    fn socket_syn_sent_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let mut s = socket_with_buffer_sizes(tx_len, rx_len);
        s.socket.state.conn_mgmt.tcp_state = State::SynSent;
        s.socket.state.conn_mgmt.tuple = Some(TUPLE);
        s.socket.state.delivery.local_seq_no = LOCAL_SEQ;
        s
    }

    fn socket_syn_sent() -> TestSocket {
        socket_syn_sent_with_buffer_sizes(64, 64)
    }

    fn socket_established_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let mut s = socket_syn_received_with_buffer_sizes(tx_len, rx_len);
        s.socket.state.conn_mgmt.tcp_state = State::Established;
        s.socket.state.delivery.remote_seq_no = REMOTE_SEQ + 1;
        s.socket.state.delivery.local_seq_no = LOCAL_SEQ + 1;
        s.socket.state.delivery.remote_last_seq = LOCAL_SEQ + 1;
        s
    }

    fn socket_established() -> TestSocket {
        socket_established_with_buffer_sizes(64, 64)
    }

    // =========================================================================================//
    // Tests for CLOSED state (from tcp.rs lines 3117-3147)
    // =========================================================================================//

    #[test]
    fn test_closed_reject() {
        // Exact port of tcp.rs test_closed_reject (line 3117)
        let mut s = socket();
        // Note: In vtcp, we need to explicitly set state to Closed
        // (tcp.rs socket defaults to Closed, vtcp defaults to Established)
        s.socket.state.conn_mgmt.tcp_state = State::Closed;
        assert_eq!(s.socket.state.conn_mgmt.tcp_state, State::Closed);

        let tcp_repr = TcpRepr {
            control: TcpControl::Syn,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
    }

    #[test]
    fn test_closed_reject_after_listen() {
        // Port of tcp.rs test_closed_reject_after_listen (line 3129)
        // NOTE: This test requires listen() and close() methods which vtcp doesn't have yet
        // Marking as TODO until those are implemented
        // TODO: Implement listen() and close() methods
    }

    #[test]
    fn test_closed_close() {
        // Port of tcp.rs test_closed_close (line 3142)
        // NOTE: This test requires close() method which vtcp doesn't have yet
        // TODO: Implement close() method
    }

    // =========================================================================================//
    // Tests for ESTABLISHED state - Data Reception (from tcp.rs lines 4208-4230)
    // =========================================================================================//

    #[test]
    fn test_established_recv() {
        // Port of tcp.rs test_established_recv (line 4208)
        // This test verifies:
        // 1. Socket accepts incoming data packet
        // 2. Socket processes the data
        // 3. Data is correctly written to rx_buffer
        // 4. Sequence numbers are updated
        // 5. (In original) ACK is sent back - NOT YET IMPLEMENTED in vtcp

        let mut s = socket_established();

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        };

        // Verify packet is accepted
        assert!(s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));

        // Process the packet
        let reply = s.socket.process(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr);

        // NOTE: Original test expects ACK reply, but vtcp returns None currently
        // TODO: Implement ACK reply generation
        // Original test line 4220-4228 verifies:
        // recv!([TcpRepr { ack_number: Some(REMOTE_SEQ + 1 + 6), window_len: 58, ... }]);

        // Verify internal state changes
        assert_eq!(
            s.socket.state.delivery.remote_seq_no,
            REMOTE_SEQ + 1 + 6,
            "Remote sequence number should advance by payload length"
        );

        // Verify assembler is empty (data was contiguous and processed)
        assert!(
            s.socket.state.delivery.assembler.is_empty(),
            "Assembler should be empty after in-order data"
        );

        // NOTE: Original test verifies data can be read via rx_buffer.dequeue_many(6)
        // TODO: Add public recv() method or rx_buffer accessor
        // For now, we verify data is in the buffer by checking the buffer length
        assert_eq!(
            s.socket.state.delivery.rx_buffer.len(),
            6,
            "rx_buffer should contain 6 bytes"
        );
    }

    // =========================================================================================//
    // Tests for out-of-order data (from tcp.rs lines 7810-7852)
    // =========================================================================================//

    #[test]
    fn test_out_of_order() {
        // Port of tcp.rs test_out_of_order (line 7810)
        // This test verifies:
        // 1. Out-of-order data is buffered
        // 2. Assembler tracks the gap
        // 3. When missing data arrives, gap is filled
        // 4. All data becomes available

        let mut s = socket_established();

        // Step 1: Send out-of-order data (bytes 3-5: "def")
        let tcp_repr_ooo = TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 3,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"def"[..],
            ..SEND_TEMPL
        };

        assert!(s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr_ooo));
        let reply = s.socket.process(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr_ooo);

        // Original test expects ACK with old seq number (no advance)
        // tcp.rs line 7821-7825:
        // Some(TcpRepr { ack_number: Some(REMOTE_SEQ + 1), ... })
        // TODO: Verify ACK reply when implemented

        // Verify assembler has the gap
        assert!(
            !s.socket.state.delivery.assembler.is_empty(),
            "Assembler should have buffered out-of-order data"
        );

        // Verify sequence number hasn't advanced (still waiting for byte 0)
        assert_eq!(
            s.socket.state.delivery.remote_seq_no,
            REMOTE_SEQ + 1,
            "Remote sequence should not advance with gap"
        );

        // Original test line 7827-7831 verifies recv() returns empty buffer
        // TODO: Verify via recv() method when implemented
        assert_eq!(
            s.socket.state.delivery.rx_buffer.len(),
            0,
            "rx_buffer should be empty (data not contiguous)"
        );

        // Step 2: Send the missing data (bytes 0-5: "abcdef")
        let tcp_repr_fill = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        };

        assert!(s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr_fill));
        let reply = s.socket.process(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr_fill);

        // Original test expects ACK with advanced seq number
        // tcp.rs line 7840-7845:
        // Some(TcpRepr { ack_number: Some(REMOTE_SEQ + 1 + 6), window_len: 58, ... })
        // TODO: Verify ACK reply when implemented

        // Verify assembler is now empty (gap filled)
        assert!(
            s.socket.state.delivery.assembler.is_empty(),
            "Assembler should be empty after gap is filled"
        );

        // Verify sequence number has advanced to cover all data
        assert_eq!(
            s.socket.state.delivery.remote_seq_no,
            REMOTE_SEQ + 1 + 6,
            "Remote sequence should advance by full 6 bytes"
        );

        // Original test line 7847-7851 verifies recv() returns "abcdef"
        // TODO: Verify data content via recv() method when implemented
        assert_eq!(
            s.socket.state.delivery.rx_buffer.len(),
            6,
            "rx_buffer should contain all 6 bytes"
        );
    }

    // =========================================================================================//
    // Tests for accepts() - wrong port/IP (from tcp.rs lines 8405-8465)
    // =========================================================================================//

    #[test]
    fn test_doesnt_accept_wrong_port() {
        // Port of tcp.rs test_doesnt_accept_wrong_port (line 8405)
        let mut s = socket_established();

        // Wrong destination port
        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            dst_port: LOCAL_PORT + 1,
            ..SEND_TEMPL
        };
        assert!(
            !s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr),
            "Should reject packet with wrong destination port"
        );

        // Wrong source port
        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            src_port: REMOTE_PORT + 1,
            ..SEND_TEMPL
        };
        assert!(
            !s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr),
            "Should reject packet with wrong source port"
        );
    }

    #[test]
    fn test_doesnt_accept_wrong_ip() {
        // Port of tcp.rs test_doesnt_accept_wrong_ip (line 8428)
        let mut s = socket_established();

        #[cfg(feature = "proto-ipv4")]
        const OTHER_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 3);

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        };

        // Correct IP - should accept
        let ip_repr = IpRepr::Ipv4(Ipv4Repr {
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        });
        assert!(
            s.socket.accepts(&mut s.cx, &ip_repr, &tcp_repr),
            "Should accept packet with correct IP"
        );

        // Wrong source IP
        let ip_repr_wrong_src = IpRepr::Ipv4(Ipv4Repr {
            src_addr: OTHER_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        });
        assert!(
            !s.socket.accepts(&mut s.cx, &ip_repr_wrong_src, &tcp_repr),
            "Should reject packet with wrong source IP"
        );

        // Wrong destination IP
        let ip_repr_wrong_dst = IpRepr::Ipv4(Ipv4Repr {
            src_addr: REMOTE_ADDR,
            dst_addr: OTHER_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        });
        assert!(
            !s.socket.accepts(&mut s.cx, &ip_repr_wrong_dst, &tcp_repr),
            "Should reject packet with wrong destination IP"
        );
    }

    // =========================================================================================//
    // Tests for SYN-RECEIVED state - RST replies (from tcp.rs lines 3389-3448)
    // =========================================================================================//

    #[test]
    fn test_syn_received_ack_too_low() {
        // Port of tcp.rs test_syn_received_ack_too_low (line 3389)
        // Tests that an ACK with ack_number < local_seq_no + 1 triggers RST
        let mut s = socket_syn_received();

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ), // Should be LOCAL_SEQ + 1
            ..SEND_TEMPL
        };

        assert!(s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));

        let reply = s.socket.process(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr);

        // Should send RST
        assert!(reply.is_some(), "Should send RST for ACK too low");

        if let Some((_ip_reply, tcp_reply)) = reply {
            assert_eq!(tcp_reply.control, TcpControl::Rst, "Should be RST packet");
            assert_eq!(tcp_reply.seq_number, LOCAL_SEQ, "RST seq should be ack_number from bad packet");
            assert_eq!(tcp_reply.ack_number, None, "RST should have no ack_number");
        }

        // State should remain SYN-RECEIVED
        assert_eq!(s.socket.state.conn_mgmt.tcp_state, State::SynReceived);
    }

    #[test]
    fn test_syn_received_ack_too_high() {
        // Port of tcp.rs test_syn_received_ack_too_high (line 3419)
        // Tests that an ACK with ack_number > local_seq_no + 1 triggers RST
        let mut s = socket_syn_received();

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 2), // Should be LOCAL_SEQ + 1
            ..SEND_TEMPL
        };

        assert!(s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));

        let reply = s.socket.process(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr);

        // Should send RST
        assert!(reply.is_some(), "Should send RST for ACK too high");

        if let Some((_ip_reply, tcp_reply)) = reply {
            assert_eq!(tcp_reply.control, TcpControl::Rst, "Should be RST packet");
            assert_eq!(tcp_reply.seq_number, LOCAL_SEQ + 2, "RST seq should be ack_number from bad packet");
            assert_eq!(tcp_reply.ack_number, None, "RST should have no ack_number");
        }

        // State should remain SYN-RECEIVED
        assert_eq!(s.socket.state.conn_mgmt.tcp_state, State::SynReceived);
    }

    // =========================================================================================//
    // Tests for SYN-SENT state - RST replies (from tcp.rs lines 3810-3933)
    // =========================================================================================//

    #[test]
    fn test_syn_sent_bad_ack() {
        // Port of tcp.rs test_syn_sent_bad_ack (line 3934)
        // Tests that ACK without SYN in SYN-SENT state triggers RST if wrong seq
        let mut s = socket_syn_sent();

        // ACK with wrong ack_number in SYN-SENT state should trigger RST
        let tcp_repr = TcpRepr {
            control: TcpControl::None,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ + 2), // Wrong, should be LOCAL_SEQ + 1
            ..SEND_TEMPL
        };

        assert!(s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));

        let reply = s.socket.process(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr);

        // Should send RST
        assert!(reply.is_some(), "Should send RST for bad ACK in SYN-SENT");

        if let Some((_ip_reply, tcp_reply)) = reply {
            assert_eq!(tcp_reply.control, TcpControl::Rst, "Should be RST packet");
        }
    }

    // =========================================================================================//
    // Tests for buffer wraparound during reassembly (from tcp.rs lines 7855-7885)
    // =========================================================================================//

    #[test]
    fn test_buffer_wraparound_rx() {
        // Partial port of tcp.rs test_buffer_wraparound_rx (line 7855)
        // NOTE: Full test cannot be ported without recv()/dequeue methods
        // Original test: receives 3 bytes, dequeues them, then receives 6 more
        // This tests wraparound in the circular buffer
        //
        // What we CAN test: Basic reassembly with buffer constraints

        let mut s = socket_established_with_buffer_sizes(64, 10);

        // Send first chunk
        let tcp_repr1 = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abc"[..],
            ..SEND_TEMPL
        };

        assert!(s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr1));
        s.socket.process(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr1);

        assert_eq!(s.socket.state.delivery.rx_buffer.len(), 3);
        assert_eq!(s.socket.state.delivery.remote_seq_no, REMOTE_SEQ + 1 + 3);

        // Send second chunk (contiguous)
        let tcp_repr2 = TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 3,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"defghi"[..],
            ..SEND_TEMPL
        };

        assert!(s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr2));
        s.socket.process(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr2);

        // Verify all data received
        assert_eq!(s.socket.state.delivery.remote_seq_no, REMOTE_SEQ + 1 + 9);
        assert_eq!(s.socket.state.delivery.rx_buffer.len(), 9);
        assert!(s.socket.state.delivery.assembler.is_empty());

        // TODO: Full wraparound test requires recv() to dequeue and make room
        // Can be fully ported once recv_slice() is implemented
    }

    // =========================================================================================//
    // Summary of tests that CANNOT be ported yet due to missing vtcp functionality:
    // =========================================================================================//
    //
    // From tcp.rs CLOSED state tests:
    // - test_closed_reject_after_listen (needs listen(), close())
    // - test_closed_close (needs close())
    //
    // From tcp.rs LISTEN state tests (lines 3159-3332):
    // - test_listen_sack_option (needs control packet handling, SYN-ACK generation)
    // - test_listen_syn_win_scale_buffers (needs window scaling, SYN-ACK)
    // - test_listen_sanity (needs listen())
    // - test_listen_validation (needs listen())
    // - test_listen_twice (needs listen())
    // - test_listen_syn (needs listen(), SYN handling, state transition)
    // - test_listen_syn_reject_ack (needs listen(), ACK rejection)
    // - test_listen_rst (needs RST handling)
    // - test_listen_close (needs listen(), close())
    //
    // From tcp.rs SYN-RECEIVED state tests (lines 3333-3607):
    // - All tests need state transition logic and control packet handling
    //
    // From tcp.rs SYN-SENT state tests (lines 3631-4135):
    // - All tests need connect(), state transitions, and control packet handling
    //
    // From tcp.rs ESTABLISHED state tests that need additional features:
    // - test_established_sliding_window_recv (needs recv() method)
    // - test_established_send (needs send() method, dispatch())
    // - test_established_send_no_ack_send (needs send(), dispatch())
    // - test_established_send_buf_gt_win (needs send())
    // - test_established_send_window_shrink (needs send())
    // - test_established_receive_partially_outside_window (needs window validation)
    // - test_established_send_wrap (needs send())
    // - test_established_no_ack (needs ACK validation)
    // - test_established_bad_ack (needs challenge ACK)
    // - test_established_bad_seq (needs sequence validation)
    // - test_established_fin (needs FIN handling, state transitions)
    // - test_established_send_fin (needs close(), FIN generation)
    // - test_established_rst (needs RST handling)
    // - test_established_close (needs close())
    // - test_established_abort (needs abort())
    //
    // From tcp.rs FIN-WAIT, CLOSING, TIME-WAIT, CLOSE-WAIT, LAST-ACK tests:
    // - All need state transitions, FIN handling, and close() logic
    //
    // From tcp.rs retransmission tests (lines 5738-6664):
    // - All need send(), retransmission timers, and dispatch()
    //
    // From tcp.rs timer tests (lines 7519-7780):
    // - All need timer management
    //
    // From tcp.rs delayed ACK and Nagle tests:
    // - Need ACK delay timers and Nagle algorithm
    //
    // =========================================================================================//
    // Tests that COULD be ported with minor vtcp additions:
    // =========================================================================================//
    //
    // Just need recv() / dequeue methods:
    // - test_peek_slice
    // - test_peek_slice_buffer_wrap
    // - test_buffer_wraparound_rx
    //
    // Just need ACK reply generation in process():
    // - test_established_recv (already ported above, just missing ACK verification)
    // - test_out_of_order (already ported above, just missing ACK verification)
    //
    // Just need RST reply generation:
    // - test_doesnt_accept_wrong_port
    // - test_doesnt_accept_wrong_ip
    //
}
