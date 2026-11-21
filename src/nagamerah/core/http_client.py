import httpx, asyncio
async def request(method,url,**kwargs):
    timeout=kwargs.pop("timeout",15); retries=kwargs.pop("retries",3)
    async with httpx.AsyncClient(timeout=timeout,verify=True,headers={"User-Agent":"NAGAMERAH/1.0.0"}) as client:
        for attempt in range(retries+1):
            try:
                response=await client.request(method,url,**kwargs)
                if response.status_code==429 or response.status_code>=500:
                    if attempt<retries: await asyncio.sleep(min(2**attempt,8)); continue
                response.raise_for_status(); return response
            except (httpx.TimeoutException,httpx.TransportError):
                if attempt>=retries: raise
                await asyncio.sleep(min(2**attempt,8))
