// fereastra glisanta anti-replay (stil IPsec/WireGuard) pe counter-ul pachetelor de date
// accepta reordonare UDP in ultimele WINDOW pachete, respinge duplicate si pachete prea vechi

const WINDOW: u64 = 64;

#[derive(Default)]
pub struct ReplayWindow {
    top: u64,
    bitmap: u64,
    seen_any: bool,
}

impl ReplayWindow {
    // doar verificare - update se face dupa ce pachetul trece de AEAD,
    // altfel un atacator poate muta fereastra cu pachete false
    pub fn check(&self, n: u64) -> bool {
        if !self.seen_any || n > self.top {
            return true;
        }
        let diff = self.top - n;
        diff < WINDOW && self.bitmap & (1 << diff) == 0
    }

    pub fn update(&mut self, n: u64) {
        if !self.seen_any {
            self.top = n;
            self.bitmap = 1;
            self.seen_any = true;
        } else if n > self.top {
            let shift = n - self.top;
            self.bitmap = if shift >= WINDOW { 0 } else { self.bitmap << shift };
            self.bitmap |= 1;
            self.top = n;
        } else {
            self.bitmap |= 1 << (self.top - n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accept(w: &mut ReplayWindow, n: u64) -> bool {
        if w.check(n) {
            w.update(n);
            true
        } else {
            false
        }
    }

    #[test]
    fn in_order_and_duplicates() {
        let mut w = ReplayWindow::default();
        assert!(accept(&mut w, 0));
        assert!(accept(&mut w, 1));
        assert!(!accept(&mut w, 1));
        assert!(!accept(&mut w, 0));
    }

    #[test]
    fn reordering_inside_window() {
        let mut w = ReplayWindow::default();
        assert!(accept(&mut w, 10));
        assert!(accept(&mut w, 5));
        assert!(accept(&mut w, 7));
        assert!(!accept(&mut w, 5));
    }

    #[test]
    fn too_old_rejected() {
        let mut w = ReplayWindow::default();
        assert!(accept(&mut w, 100));
        assert!(!accept(&mut w, 100 - WINDOW));
        assert!(accept(&mut w, 100 - WINDOW + 1));
    }

    #[test]
    fn big_jump_clears_bitmap() {
        let mut w = ReplayWindow::default();
        assert!(accept(&mut w, 1));
        assert!(accept(&mut w, 1000));
        assert!(accept(&mut w, 999));
        assert!(!accept(&mut w, 1));
    }
}
