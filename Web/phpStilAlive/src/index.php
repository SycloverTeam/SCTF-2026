<?php
error_reporting(0);

function default_code(): string
{
    return <<<'PHP'
<?php
$name = "phpstilAlive";
echo "hello, {$name}\n";
echo PHP_VERSION . "\n";
PHP;
}

function normalize_snippet(string $code): string
{
    $code = preg_replace('/^\xEF\xBB\xBF/', '', $code);
    $code = preg_replace('/^\s*<\?(?:php)?/i', '', $code);
    $code = preg_replace('/\?>\s*$/', '', $code);
    return $code;
}

function token_text(mixed $token): string
{
    return is_array($token) ? $token[1] : $token;
}

function token_id(mixed $token): ?int
{
    return is_array($token) ? $token[0] : null;
}

function is_name_token(mixed $token): bool
{
    if (!is_array($token)) {
        return false;
    }

    $name_tokens = [
        T_STRING,
        T_NAME_FULLY_QUALIFIED,
        T_NAME_QUALIFIED,
        T_NAME_RELATIVE,
    ];
    return in_array($token[0], $name_tokens, true);
}

function normalized_name(string $name): string
{
    $name = strtolower(ltrim($name, '\\'));
    $parts = explode('\\', $name);
    return end($parts) ?: $name;
}

function next_significant_token(array $tokens, int $index): ?int
{
    $skip = [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT];
    for ($i = $index + 1, $n = count($tokens); $i < $n; $i++) {
        if (is_array($tokens[$i]) && in_array($tokens[$i][0], $skip, true)) {
            continue;
        }
        return $i;
    }
    return null;
}

function snippet_is_blocked(string $code): bool
{
    $blocked_names = [
        'arrayiterator' => true,
        'arrayobject' => true,
        'dateinterval' => true,
        'datetime' => true,
        'datetimeimmutable' => true,
        'dateperiod' => true,
        'hashcontext' => true,
        'multipleiterator' => true,
        'recursivearrayiterator' => true,
        'spldoublylinkedlist' => true,
        'splheap' => true,
        'splmaxheap' => true,
        'splminheap' => true,
        'splobjectstorage' => true,
        'weakmap' => true,
        'weakreference' => true,
    ];
    $blocked_calls = [
        'date_create' => true,
        'date_create_immutable' => true,
        'date_diff' => true,
        'date_interval_create_from_date_string' => true,
        'prev' => true,
        'session_start' => true,
        'session_unset' => true,
        'settype' => true,
        'spl_autoload_register' => true,
        'spl_autoload_unregister' => true,
        'call_user_func' => true,
        'call_user_func_array' => true,
    ];
    $tokens = token_get_all("<?php\n" . $code);

    foreach ($tokens as $i => $token) {
        if (is_name_token($token)) {
            $name = normalized_name(token_text($token));
            if (isset($blocked_names[$name])) {
                return true;
            }

            $next = next_significant_token($tokens, $i);
            if ($next !== null && token_text($tokens[$next]) === '(' && isset($blocked_calls[$name])) {
                return true;
            }
        }

        $id = token_id($token);
        if ($id === T_CLONE) {
            return true;
        }

        if ($id === T_CONSTANT_ENCAPSED_STRING || $id === T_ENCAPSED_AND_WHITESPACE) {
            $text = strtolower(token_text($token));
            foreach ($blocked_names as $name => $_) {
                if (str_contains($text, $name)) {
                    return true;
                }
            }
            foreach ($blocked_calls as $name => $_) {
                if (str_contains($text, $name)) {
                    return true;
                }
            }
        }

        if ($id === T_NEW) {
            $next = next_significant_token($tokens, $i);
            if ($next !== null) {
                $next_id = token_id($tokens[$next]);
                if ($next_id === T_VARIABLE || token_text($tokens[$next]) === '(') {
                    return true;
                }
            }
        }
    }

    return false;
}

function run_snippet(string $code): string
{
    if (strlen($code) > 65536) {
        return "input is too large\n";
    }

    $code = normalize_snippet($code);
    if (snippet_is_blocked($code)) {
        return "input rejected\n";
    }

    ob_start();
    try {
        eval($code);
    } catch (Throwable $e) {
        echo get_class($e), ': ', $e->getMessage(), "\n";
    }
    $output = ob_get_clean();

    if ($output === '') {
        return "(no output)\n";
    }
    return $output;
}

function html(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function page(string $code, string $output = ''): void
{
    echo '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">';
    echo '<meta name="viewport" content="width=device-width, initial-scale=1">';
    echo '<title>在线运行PHP</title><style>';
    echo ':root{color-scheme:light;--bg:#f5f6f8;--panel:#fff;--line:#d9dde5;--ink:#1f2937;--muted:#667085;--blue:#2f6fed;--code:#111827}';
    echo '*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 Arial,"Microsoft YaHei",sans-serif}';
    echo '.top{height:54px;background:#252b33;color:#fff;display:flex;align-items:center;padding:0 24px;font-size:18px;font-weight:600}';
    echo '.wrap{max-width:1180px;margin:22px auto;padding:0 18px}.crumb{color:var(--muted);margin-bottom:14px}.panel{background:var(--panel);border:1px solid var(--line);border-radius:4px;overflow:hidden}';
    echo '.bar{height:46px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:0 14px;background:#fafafa}.bar strong{font-size:16px}.tag{color:#475467;border:1px solid var(--line);padding:5px 9px;border-radius:3px;background:#fff}';
    echo 'textarea{width:100%;min-height:390px;border:0;display:block;resize:vertical;padding:14px 16px;color:var(--code);font:14px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;outline:none;background:#fff}';
    echo '.actions{display:flex;gap:10px;align-items:center;padding:12px 14px;border-top:1px solid var(--line);background:#fafafa}.run{border:0;border-radius:3px;background:var(--blue);color:#fff;padding:9px 24px;cursor:pointer;font-weight:600}.muted{color:var(--muted)}';
    echo '.out{margin-top:18px;background:#111827;color:#d1fae5;border-radius:4px;min-height:170px;padding:14px 16px;white-space:pre-wrap;word-break:break-word;font:14px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}';
    echo '</style></head><body><div class="top">在线运行PHP</div><main class="wrap">';
    echo '<div class="crumb">首页 / 后端 / PHP在线运行</div><form method="post" class="panel">';
    echo '<div class="bar"><strong>PHP 代码</strong><span class="tag">PHP 8.4</span></div>';
    echo '<textarea name="code" spellcheck="false">', html($code), '</textarea>';
    echo '<div class="actions"><button class="run" type="submit">运行代码</button><span class="muted">stdout / stderr</span></div>';
    echo '</form><pre class="out">', html($output === '' ? "点击运行查看输出\n" : $output), '</pre>';
    echo '</main></body></html>';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $code = $_POST['code'] ?? '';
    if (!is_string($code)) {
        $code = '';
    }
    page($code, run_snippet($code));
    exit;
}

page(default_code());
