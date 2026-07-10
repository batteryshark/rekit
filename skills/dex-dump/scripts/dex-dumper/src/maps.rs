// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 rekit contributors

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Region {
    pub start: usize,
    pub end: usize,
}

impl Region {
    pub fn len(self) -> usize {
        self.end - self.start
    }

    pub fn contains(self, start: usize, len: usize) -> bool {
        len > 0 && start >= self.start && start.checked_add(len).is_some_and(|end| end <= self.end)
    }
}

pub fn parse_readable_regions(maps: &str) -> Vec<Region> {
    let mut regions = Vec::<Region>::new();
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let Some(range) = fields.next() else {
            continue;
        };
        let Some(perms) = fields.next() else {
            continue;
        };
        if !perms.starts_with('r') {
            continue;
        }
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (
            usize::from_str_radix(start, 16),
            usize::from_str_radix(end, 16),
        ) else {
            continue;
        };
        if start >= end {
            continue;
        }

        // Adjacent readable mappings can jointly contain one runtime image.
        if let Some(previous) = regions.last_mut() {
            if previous.end == start {
                previous.end = end;
                continue;
            }
        }
        regions.push(Region { start, end });
    }
    regions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_readable_regions_and_coalesces_neighbors() {
        let maps = concat!(
            "1000-2000 r--p 00000000 00:00 0 /first\n",
            "2000-2800 rw-p 00000000 00:00 0\n",
            "2800-3000 ---p 00000000 00:00 0\n",
            "4000-5000 r-xp 00000000 00:00 0 /second name\n",
            "broken\n",
        );
        assert_eq!(
            parse_readable_regions(maps),
            vec![
                Region {
                    start: 0x1000,
                    end: 0x2800,
                },
                Region {
                    start: 0x4000,
                    end: 0x5000,
                },
            ]
        );
    }

    #[test]
    fn containment_checks_overflow_and_edges() {
        let region = Region {
            start: 100,
            end: 200,
        };
        assert_eq!(region.len(), 100);
        assert!(region.contains(100, 100));
        assert!(!region.contains(99, 1));
        assert!(!region.contains(200, 1));
        assert!(!region.contains(usize::MAX - 1, 8));
    }
}
