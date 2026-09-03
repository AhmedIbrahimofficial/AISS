import asyncio, time
from dotenv import load_dotenv; load_dotenv()
import sys; sys.path.insert(0,'.')

async def main():
    t0 = time.time()
    from core.security_config import security_config
    await security_config.validate()
    print('security_config: %.1fs' % (time.time()-t0))
    
    t1 = time.time()
    from core.licensing import license_manager
    await license_manager.validate()
    print('license: %.1fs' % (time.time()-t1))
    
    t2 = time.time()
    from core.startup_validator import run_startup_checks
    await run_startup_checks()
    print('startup_checks: %.1fs' % (time.time()-t2))
    
    t3 = time.time()
    from core.database import init_db
    await init_db()
    print('init_db: %.1fs' % (time.time()-t3))
    
    t4 = time.time()
    from core.websocket_manager import WebSocketManager
    from core.threat_engine import ThreatEngine
    ws = WebSocketManager()
    te = ThreatEngine(ws)
    await te.startup()
    print('threat_engine: %.1fs' % (time.time()-t4))
    print('TOTAL: %.1fs' % (time.time()-t0))

asyncio.run(main())
