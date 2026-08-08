import { useEffect, useRef, useState } from "react";

export function useCountUp(target: number, decimals = 0) {
  const [value, setValue] = useState(0);
  const frame = useRef(0);

  useEffect(() => {
    const start = performance.now();
    const from = 0;
    const tick = (t: number) => {
      const p = Math.min(1, (t - start) / 900);
      const eased = 1 - Math.pow(1 - p, 3);
      setValue(from + (target - from) * eased);
      if (p < 1) frame.current = requestAnimationFrame(tick);
    };
    frame.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame.current);
  }, [target]);

  return value.toFixed(decimals);
}
