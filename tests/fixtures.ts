export const baseMatrix = [
  [2, 2.3, 4],
  [7, 7.8, 7],
  [4.442, 3, 9]
] as const;

export const azimuthPitchRollMatrix = [
  [0.12, 0.78, -0.35],
  [1.57, -0.42, 0.05],
  [2.09, 0.31, -1.2],
  [3.14, -0.85, 0.42]
] as const;

export const positionMatrix = [
  // positional angles (e.g., azimuth/elevation)
  [0.22, 1.08],
  // latitude/longitude
  [37.7749, -122.4194],
  // another angle set with a third component (e.g., roll)
  [1.57, -0.42, 0.05],
  // latitude/longitude
  [-33.8688, 151.2093]
] as const;

export const positionLatLongPairs = [
  { rowIndex: 1, latitude: 37.7749, longitude: -122.4194 },
  { rowIndex: 3, latitude: -33.8688, longitude: 151.2093 }
] as const;
