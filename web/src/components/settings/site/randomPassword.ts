/** A random password from letters and digits (no look-alikes), from the browser's CSPRNG. */
export function randomPassword(n = 24): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const out: string[] = [];
  const buf = new Uint32Array(1);
  while (out.length < n) {
    crypto.getRandomValues(buf);
    // Rejection sampling keeps every character equally likely.
    if (buf[0] < Math.floor(2 ** 32 / alphabet.length) * alphabet.length)
      out.push(alphabet[buf[0] % alphabet.length]);
  }
  return out.join("");
}
