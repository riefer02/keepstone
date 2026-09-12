//! Geospatial addressing via H3 cells.

use core::fmt;

use h3o::{CellIndex, LatLng, Resolution};

use crate::error::CoreError;

/// A geospatial cell address (an H3 cell).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CellId {
    index: CellIndex,
}

impl CellId {
    /// Compute the H3 cell containing `(lat, lng)` at `resolution` (0–15).
    ///
    /// # Errors
    /// Returns [`CoreError::Cell`] for invalid coordinates or resolution.
    pub fn from_lat_lng(lat: f64, lng: f64, resolution: u8) -> Result<Self, CoreError> {
        let latlng = LatLng::new(lat, lng).map_err(|e| CoreError::Cell(e.to_string()))?;
        let resolution =
            Resolution::try_from(resolution).map_err(|e| CoreError::Cell(e.to_string()))?;
        Ok(Self {
            index: latlng.to_cell(resolution),
        })
    }

    /// Parse an H3 cell from its hexadecimal string form.
    ///
    /// # Errors
    /// Returns [`CoreError::Cell`] if the string is not a valid cell.
    pub fn parse_hex(text: &str) -> Result<Self, CoreError> {
        let index: CellIndex = text.parse().map_err(|e| CoreError::Cell(format!("{e}")))?;
        Ok(Self { index })
    }

    /// The H3 hexadecimal representation.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.index.to_string()
    }

    /// The H3 resolution of this cell.
    #[must_use]
    pub fn resolution(&self) -> u8 {
        u8::from(self.index.resolution())
    }

    /// All cells within grid distance `k` (the "k-ring"), including this cell.
    #[must_use]
    pub fn ring(&self, k: u32) -> Vec<Self> {
        let cells: Vec<CellIndex> = self.index.grid_disk(k);
        cells.into_iter().map(|index| Self { index }).collect()
    }
}

impl fmt::Debug for CellId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CellId({})", self.index)
    }
}

impl fmt::Display for CellId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_round_trips_through_hex() {
        let cell = CellId::from_lat_lng(51.5007, -0.1246, 9).unwrap();
        let parsed = CellId::parse_hex(&cell.to_hex()).unwrap();
        assert_eq!(cell, parsed);
        assert_eq!(cell.resolution(), 9);
    }

    #[test]
    fn ring_contains_center_and_neighbors() {
        let cell = CellId::from_lat_lng(48.8584, 2.2945, 9).unwrap();
        let ring = cell.ring(1);
        assert_eq!(ring.len(), 7);
        assert!(ring.contains(&cell));
    }

    #[test]
    fn invalid_resolution_is_rejected() {
        assert!(CellId::from_lat_lng(0.0, 0.0, 20).is_err());
    }
}
