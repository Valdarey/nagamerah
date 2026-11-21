import asyncio
class RateLimiter:
    def __init__(self, limit=4, period=60): self.limit=limit; self.period=period; self._times=[]; self._lock=asyncio.Lock()
    async def acquire(self):
        import time
        async with self._lock:
            now=time.monotonic(); self._times=[t for t in self._times if now-t<self.period]
            if len(self._times)>=self.limit: await asyncio.sleep(max(0,self.period-(now-self._times[0])))
            self._times.append(time.monotonic())
