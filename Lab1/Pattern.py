class Pattern:
    def __init__(self, 
            vulnerable_name: str,
            sources: list[str], 
            sinks: list[str] = None, 
            sanitizers: list[str] = None
            ) -> None:
        self._vulnerable_name = vulnerable_name
        self._sources = sources if sources is not None else []
        self._sinks = sinks if sinks is not None else []
        self._sanitizers = sanitizers if sanitizers is not None else []

    @property
    def get_vulnerable_name(self):
        return self._vulnerable_name

    def set_vulnerable_name(self, value):
        self._vulnerable_name = value

    @property
    def get_sources(self):
        return self._sources

    def set_sources(self, value):
        self._sources = value

    @property
    def get_sinks(self):
        return self._sinks

    def set_sinks(self, value):
        self._sinks = value

    @property
    def get_sanitizers(self):
        return self._sanitizers

    def set_sanitizers(self, value):
        self._sanitizers = value

    def is_source(self, item: str) -> bool:
        return item in self._sources

    def is_sink(self, item: str) -> bool:
        return item in self._sinks

    def is_sanitizer(self, item: str) -> bool:
        return item in self._sanitizers
