from abc import ABC,abstractmethod
class Provider(ABC):
    name="base"; supported_types=set()
    def is_configured(self): return True
    @abstractmethod
    async def lookup(self,ioc): ...
