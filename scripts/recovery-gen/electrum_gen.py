# Writes two Electrum wallets with Electrum's own create_new_wallet (throwaway seeds, fixed throwaway password).
# argv: outdir password. Prints nothing secret; seeds go to files in outdir (a temp dir).
import sys, os
from electrum.simple_config import SimpleConfig
from electrum.wallet import create_new_wallet
from electrum import util
out, pw = sys.argv[1], sys.argv[2]
cfg = SimpleConfig({'cwd': out, 'offline': True, 'electrum_path': os.path.join(out, 'edir')})
loop, stop, thr = util.create_and_start_event_loop()
for name, enc in (('electrum-fileenc', True), ('electrum-keyenc', False)):
    p = os.path.join(out, name)
    d = create_new_wallet(path=p, config=cfg, password=pw, encrypt_file=enc, seed_type='segwit')
    open(p + '.seed', 'w').write(d['seed'] + '\n')
    open(p + '.want', 'w').write('\n'.join(d['wallet'].get_receiving_addresses()[:3]) + '\n')
loop.call_soon_threadsafe(stop.set_result, 1); thr.join(5)
