// Abramowitz-Stegun approximation used in Black-Scholes pricing
export const cnd = (x: number): number => {
  const a1 = 0.31938153
  const a2 = -0.356563782
  const a3 = 1.781477937
  const a4 = -1.821255978
  const a5 = 1.330274429
  const k = 1 / (1 + 0.2316419 * Math.abs(x))
  const poly = k * (a1 + k * (a2 + k * (a3 + k * (a4 + k * a5))))
  const value = 1 - 0.398942280401 * Math.exp((-x * x) / 2) * poly
  return x < 0 ? 1 - value : value
}
