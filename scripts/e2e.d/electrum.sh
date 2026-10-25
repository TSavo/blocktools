# Electrum 2.x seeds (public vectors from Electrum's own test suite) through the boundary
echo '{"mnemonic":"cycle rocket west magnet parrot shuffle foot correct salt library feed song"}' | boundary el-std '1NNkttn1YvVGdqBW4PR6zvc3Zx3H5owKRf' 'seed-to-master | derive --chain btc --count 1'
echo '{"mnemonic":"bitter grass shiver impose acquire brush forget axis eager alone wine silver"}' | boundary el-sw 'bc1q3g5tmkmlvxryhh843v4dz026avatc0zzr6h3af' 'seed-to-master | derive --chain btc --count 1'
