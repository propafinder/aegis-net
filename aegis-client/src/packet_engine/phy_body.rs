struct Phy {
    input: VecDeque<Vec<u8>>,
    output: VecDeque<Vec<u8>>,
    mtu: usize,
}
struct Rx {
    packet: Vec<u8>,
}
struct Tx<'a> {
    output: &'a mut VecDeque<Vec<u8>>,
}
impl Device for Phy {
    type RxToken<'a>
        = Rx
    where
        Self: 'a;
    type TxToken<'a>
        = Tx<'a>
    where
        Self: 'a;
    fn receive(&mut self, _: SmolInstant) -> Option<(Rx, Tx<'_>)> {
        if self.output.len() >= MAX_PACKET_QUEUE {
            return None;
        }
        Some((
            Rx {
                packet: self.input.pop_front()?,
            },
            Tx {
                output: &mut self.output,
            },
        ))
    }
    fn transmit(&mut self, _: SmolInstant) -> Option<Tx<'_>> {
        (self.output.len() < MAX_PACKET_QUEUE).then_some(Tx {
            output: &mut self.output,
        })
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}
impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.packet)
    }
}
impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.output.push_back(packet);
        result
    }
}
