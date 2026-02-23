from cachetools import TTLCache

mx_cache = TTLCache(maxsize=50000, ttl=3600)
domain_flags_cache = TTLCache(maxsize=50000, ttl=21600)  # catch_all, esp, etc.
