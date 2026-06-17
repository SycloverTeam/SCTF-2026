import React, { ChangeEvent, FormEvent, useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Hammer, MessageCircle, Palette, ShoppingBag, Sparkles, Wrench } from 'lucide-react';
import './styles.css';

type User = {
  id: number;
  username: string;
  coins: number;
  role: string;
  vipLevel: number;
  createdAt: string;
  woodfishCount: number;
};

type Product = {
  id: number;
  name: string;
  description: string;
  price: number;
  image: string;
};

type ChatMessage = {
  id: number;
  username: string;
  content: string;
  createdAt: string;
};

type Page = 'shop' | 'chat' | 'louvre' | 'woodfish';
type BotState = 'normal' | 'thinking' | 'complete';

type LouvreOptions = {
  threshold: number;
  blurRadius: number;
  lineWeight: number;
  maxSize: number;
  background: string;
  fromColor: string;
  toColor: string;
  direction: 'vertical' | 'horizontal' | 'diagonal';
  invert: boolean;
};

const TOKEN_KEY = 'webshop_token';
const USERNAME_RE = /^[A-Za-z0-9_]+$/;
const STRONG_PASSWORD_RE = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9])\S{12,128}$/;

function formatApiError(data: unknown): string {
  if (!data || typeof data !== 'object') return '请求失败';
  const detail = (data as { detail?: unknown }).detail;
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((item) => {
        if (!item || typeof item !== 'object') return String(item);
        const record = item as { msg?: unknown; loc?: unknown };
        const loc = Array.isArray(record.loc) ? record.loc.filter((part) => part !== 'body').join('.') : '';
        const msg = typeof record.msg === 'string' ? record.msg : JSON.stringify(item);
        return loc ? `${loc}: ${msg}` : msg;
      })
      .join(', ');
  }
  return '请求失败';
}

async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = localStorage.getItem(TOKEN_KEY);
  const headers = new Headers(options.headers);
  headers.set('Content-Type', 'application/json');
  if (token) headers.set('Authorization', `Bearer ${token}`);
  const response = await fetch(path, { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(formatApiError(data));
  return data as T;
}

async function apiForm<T>(path: string, body: FormData): Promise<T> {
  const token = localStorage.getItem(TOKEN_KEY);
  const headers = new Headers();
  if (token) headers.set('Authorization', `Bearer ${token}`);
  const response = await fetch(path, { method: 'POST', headers, body });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(formatApiError(data));
  return data as T;
}

async function downloadProtected(path: string, filename: string) {
  const token = localStorage.getItem(TOKEN_KEY);
  const headers = new Headers();
  if (token) headers.set('Authorization', `Bearer ${token}`);
  const response = await fetch(path, { headers });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(formatApiError(data));
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

const u8 = (...v: number[]) => String.fromCharCode(...v);
const join = (...v: string[]) => v.join('');

function makeChatEnvelope(content: string, probe: boolean) {
  const k0 = u8(108, 99);
  const k1 = u8(116, 121, 112, 101);
  const k2 = u8(105, 100);
  const k3 = u8(107, 119, 97, 114, 103, 115);
  const kc = u8(99, 111, 110, 116, 101, 110, 116);
  const source = u8(115, 111, 117, 114, 99, 101);
  const client = u8(99, 108, 105, 101, 110, 116);
  const ts = u8(116, 115);
  const messages = u8(109, 101, 115, 115, 97, 103, 101, 115);
  const ns0 = join(u8(108, 97, 110, 103, 99, 104, 97, 105, 110), u8(95, 99, 111, 114, 101));
  const ns1 = u8(109, 101, 115, 115, 97, 103, 101, 115);
  const cls = join(u8(83, 121, 115), u8(116, 101, 109), u8(77, 101, 115, 115, 97, 103, 101));

  return {
    [source]: probe ? join(u8(97, 115, 115, 101, 116), '-', u8(112, 114, 111, 98, 101)) : 'chat-sync',
    [client]: 'web-shop',
    [ts]: Date.now(),
    [messages]: probe
      ? [
          {
            [k0]: 1,
            [k1]: u8(99, 111, 110, 115, 116, 114, 117, 99, 116, 111, 114),
            [k2]: [ns0, ns1, cls],
            [k3]: {
              [kc]: 'Support replay context initialized.'
            }
          }
        ]
      : [
          {
            [k1]: 'text',
            [kc]: content
          }
        ]
  };
}

async function loadChatSprite() {
  await new Promise<void>((resolve) => {
    const img = new Image();
    img.onload = () => resolve();
    img.onerror = () => resolve();
    img.src = `/bot_imgs/normal.png?v=${Date.now()}`;
  });
  await api<Record<string, unknown>>('/api/chat/presence', {
    method: 'POST',
    body: JSON.stringify({
      content: 'alive',
      metadata: makeChatEnvelope('alive', true)
    })
  });
}

function App() {
  const [token, setToken] = useState(localStorage.getItem(TOKEN_KEY));
  const [user, setUser] = useState<User | null>(null);
  const [page, setPage] = useState<Page>('shop');

  useEffect(() => {
    if (!token) {
      setUser(null);
      return;
    }
    api<{ user: User }>('/api/auth/me')
      .then((res) => setUser(res.user))
      .catch(() => {
        localStorage.removeItem(TOKEN_KEY);
        setToken(null);
      });
  }, [token]);

  const onAuthed = (newToken: string, newUser: User) => {
    localStorage.setItem(TOKEN_KEY, newToken);
    setToken(newToken);
    setUser(newUser);
  };

  const logout = () => {
    localStorage.removeItem(TOKEN_KEY);
    setToken(null);
    setUser(null);
  };

  if (!token || !user) return <AuthPage onAuthed={onAuthed} />;

  return (
    <div className="app-shell">
      <Navbar page={page} setPage={setPage} user={user} onLogout={logout} />
      <main className="main-panel">
        {page === 'shop' && <ShopPage refreshUser={setUser} />}
        {page === 'chat' && <ChatPage />}
        {page === 'louvre' && <LouvrePage />}
        {page === 'woodfish' && <WoodfishPage user={user} refreshUser={setUser} />}
      </main>
      <FloatingBot user={user} refreshUser={setUser} />
    </div>
  );
}

function AuthPage({ onAuthed }: { onAuthed: (token: string, user: User) => void }) {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');

  const title = mode === 'login' ? '登录 Web Shop' : '注册新账号';
  const subtitle = mode === 'login' ? '使用已有账号进入商店。' : '新账号初始拥有 50 金币。';
  const action = mode === 'login' ? '登录' : '注册';

  const validate = () => {
    const trimmedUsername = username.trim();
    if (!trimmedUsername) return '请输入用户名';
    if (mode === 'register' && trimmedUsername.length < 3) return '用户名至少 3 个字符';
    if (trimmedUsername.length > 32) return '用户名最多 32 个字符';
    if (mode === 'register' && !USERNAME_RE.test(trimmedUsername)) return '用户名只能包含字母、数字和下划线';
    if (!password) return '请输入密码';
    if (mode === 'register' && password.length < 12) return '密码至少 12 个字符';
    if (password.length > 128) return '密码最多 128 个字符';
    if (mode === 'register' && !STRONG_PASSWORD_RE.test(password)) return '密码必须包含大小写字母、数字、特殊字符，且不能包含空白字符';
    if (mode === 'register' && password.toLowerCase().includes(trimmedUsername.toLowerCase())) return '密码不能包含用户名';
    if (mode === 'register' && !confirmPassword) return '请确认密码';
    if (mode === 'register' && password !== confirmPassword) return '两次输入的密码不一致';
    return '';
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError('');
    const validationError = validate();
    if (validationError) {
      setError(validationError);
      return;
    }
    try {
      const body =
        mode === 'register'
          ? { username: username.trim(), password, confirmPassword }
          : { username: username.trim(), password };
      const res = await api<{ token: string; user: User }>(`/api/auth/${mode}`, {
        method: 'POST',
        body: JSON.stringify(body)
      });
      onAuthed(res.token, res.user);
    } catch (err) {
      setError(err instanceof Error ? err.message : '操作失败');
    }
  };

  const switchMode = () => {
    setMode(mode === 'login' ? 'register' : 'login');
    setPassword('');
    setConfirmPassword('');
    setError('');
  };

  return (
    <div className="auth-page">
      <section className={`auth-card ${mode === 'register' ? 'register-card' : 'login-card'}`}>
        <div className="brand-mark">
          <ShoppingBag size={30} />
        </div>
        <div className="auth-head">
          <h1>{title}</h1>
          <p>{subtitle}</p>
        </div>
        <form onSubmit={submit} className="auth-form">
          <label>
            用户名
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder={mode === 'login' ? '请输入用户名' : '3-32 位字母、数字或下划线'}
              autoComplete="username"
            />
          </label>
          <label>
            密码
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={mode === 'login' ? '请输入密码' : '至少 12 位，含大小写、数字和特殊字符'}
              autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
            />
          </label>
          {mode === 'register' && (
            <label>
              确认密码
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="请再次输入密码"
                autoComplete="new-password"
              />
            </label>
          )}
          {error && <div className="error-box">{error}</div>}
          <button type="submit">{action}</button>
        </form>
        <button className="link-button" onClick={switchMode}>
          {mode === 'login' ? '没有账号？创建一个' : '已有账号？返回登录'}
        </button>
      </section>
    </div>
  );
}

function Navbar({
  page,
  setPage,
  user,
  onLogout
}: {
  page: Page;
  setPage: (page: Page) => void;
  user: User;
  onLogout: () => void;
}) {
  const items: { key: Page; label: string }[] = [
    { key: 'shop', label: '商店' },
    { key: 'chat', label: '聊天区' },
    { key: 'louvre', label: '卢浮宫生成器' },
    { key: 'woodfish', label: '敲木鱼' }
  ];

  return (
    <header className="navbar">
      <div className="nav-brand">
        <ShoppingBag size={24} />
        <span>Web Shop</span>
      </div>
      <nav>
        {items.map((item) => (
          <button key={item.key} className={page === item.key ? 'active' : ''} onClick={() => setPage(item.key)}>
            {item.label}
          </button>
        ))}
      </nav>
      <div className="nav-right">
        <div className="user-pill">
          <span>{user.username}</span>
          <b>
            {user.coins} 金币 | {user.role}
          </b>
        </div>
        <button onClick={onLogout}>退出</button>
      </div>
    </header>
  );
}

function WoodfishPage({ user, refreshUser }: { user: User; refreshUser: (user: User) => void }) {
  const [message, setMessage] = useState('');
  const [knocking, setKnocking] = useState(false);
  const broken = user.woodfishCount >= 10;

  const knock = async () => {
    if (broken || knocking) return;
    setKnocking(true);
    try {
      const res = await api<{ ok: boolean; broken: boolean; message: string; user: User }>('/api/woodfish/knock', {
        method: 'POST',
        body: '{}'
      });
      refreshUser(res.user);
      setMessage(res.message);
    } catch (err) {
      setMessage(err instanceof Error ? err.message : '木鱼请求失败');
    } finally {
      window.setTimeout(() => setKnocking(false), 220);
    }
  };

  return (
    <section className="page-section woodfish-page">
      <div className="section-head">
        <div>
          <p className="eyebrow">WOODFISH</p>
          <h2>敲木鱼</h2>
        </div>
        <div className="coin-card">余额：{user.coins} 金币</div>
      </div>
      <div className="woodfish-stage">
        <button
          className={`woodfish-object ${knocking ? 'knocking' : ''} ${broken ? 'broken' : ''}`}
          onClick={knock}
          disabled={broken}
          aria-label="敲木鱼"
        >
          <span className="woodfish-body" />
          <span className="woodfish-mouth" />
          <span className="woodfish-hammer">
            <Hammer size={54} />
          </span>
        </button>
        <div className="woodfish-info">
          <strong>{broken ? '木鱼坏掉了' : `已敲 ${user.woodfishCount} 次`}</strong>
          {message && <em>{message}</em>}
        </div>
      </div>
    </section>
  );
}

function ShopPage({ refreshUser }: { refreshUser: (user: User) => void }) {
  const [products, setProducts] = useState<Product[]>([]);
  const [coins, setCoins] = useState(0);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const load = () => {
    api<{ products: Product[]; coins: number }>('/api/shop/products')
      .then((res) => {
        setProducts(res.products);
        setCoins(res.coins);
      })
      .catch((err) => setError(err instanceof Error ? err.message : '加载失败'));
    api<{ user: User }>('/api/auth/me')
      .then((res) => refreshUser(res.user))
      .catch(() => {});
  };

  useEffect(load, [refreshUser]);

  const buy = async (product: Product) => {
    setError('');
    setNotice('');
    try {
      const res = await api<{ message: string; user: User; download?: string }>('/api/shop/buy', {
        method: 'POST',
        body: JSON.stringify({ productId: product.id })
      });
      refreshUser(res.user);
      setCoins(res.user.coins);
      if (res.download) {
        await downloadProtected(res.download, 'support_ticket.py');
        setNotice(`${res.message} 已下载 support_ticket.py`);
      } else {
        setNotice(res.message);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : '购买失败');
    }
  };

  return (
    <section className="page-section">
      <div className="section-head">
        <div>
          <p className="eyebrow">STORE</p>
          <h2>商店</h2>
        </div>
        <div className="coin-card">余额：{coins} 金币</div>
      </div>
      {error && <div className="error-box">{error}</div>}
      {notice && <div className="success-box">{notice}</div>}
      <div className="product-grid">
        {products.map((product) => (
          <article className="product-card" key={product.id}>
            <img src={product.image} alt={product.name} />
            <div>
              <h3>{product.name}</h3>
              <p>{product.description}</p>
            </div>
            <footer>
              <span>{product.price} 金币</span>
              <button onClick={() => buy(product)} disabled={coins < product.price}>
                {coins < product.price ? '金币不足' : '购买'}
              </button>
            </footer>
          </article>
        ))}
      </div>
    </section>
  );
}

function ChatPage() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [content, setContent] = useState('');
  const [error, setError] = useState('');
  const [historyLoaded, setHistoryLoaded] = useState(false);
  const [loading, setLoading] = useState(false);
  const logRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    let closed = false;
    const run = () => {
      if (closed) return;
      loadChatSprite().catch(() => {});
    };
    const warmup = window.setTimeout(run, 60000);
    const timer = window.setInterval(run, 60000);
    return () => {
      closed = true;
      window.clearTimeout(warmup);
      window.clearInterval(timer);
    };
  }, []);

  const loadHistory = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await api<{ messages: ChatMessage[] }>('/api/chat/messages');
      setMessages(res.messages);
      setHistoryLoaded(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : '加载聊天记录失败');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (historyLoaded) {
      logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
    }
  }, [messages, historyLoaded]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!content.trim()) return;
    setError('');
    try {
      const res = await api<{ message: ChatMessage }>('/api/chat/messages', {
        method: 'POST',
        body: JSON.stringify({ content, metadata: makeChatEnvelope(content, false) })
      });
      setMessages((old) => [...old, res.message]);
      setContent('');
    } catch (err) {
      setError(err instanceof Error ? err.message : '发送失败');
    }
  };

  return (
    <section className="page-section chat-page">
      <div className="section-head">
        <div>
          <p className="eyebrow">PUBLIC CHAT</p>
          <h2>聊天区</h2>
        </div>
      </div>
      {error && <div className="error-box">{error}</div>}
      <div className="chat-container">
        <div className="chat-messages-area" ref={logRef}>
          {!historyLoaded && messages.length === 0 && (
            <div className="chat-empty-state">
              <button className="load-history-btn" onClick={loadHistory} disabled={loading}>
                {loading ? '加载中...' : '加载聊天记录'}
              </button>
            </div>
          )}
          {historyLoaded && messages.length === 0 && <p className="empty-log">还没有消息，发送第一条吧。</p>}
          {messages.map((message) => (
            <article className="public-message" key={message.id}>
              <header>
                <b>{message.username}</b>
                <span>{new Date(message.createdAt).toLocaleString()}</span>
              </header>
              <div className="message-content" dangerouslySetInnerHTML={{ __html: message.content }} />
            </article>
          ))}
        </div>
        <form onSubmit={submit} className="chat-input-area">
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder="支持富文本和媒体内容"
            rows={3}
          />
          <button type="submit">发送</button>
        </form>
      </div>
    </section>
  );
}

function LouvrePage() {
  const [file, setFile] = useState<File | null>(null);
  const [sourceUrl, setSourceUrl] = useState('');
  const [resultUrl, setResultUrl] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [options, setOptions] = useState<LouvreOptions>({
    threshold: 22,
    blurRadius: 2,
    lineWeight: 2,
    maxSize: 900,
    background: '#050817',
    fromColor: '#00f5ff',
    toColor: '#ff2bd6',
    direction: 'vertical',
    invert: false
  });

  const updateOption = <K extends keyof LouvreOptions>(key: K, value: LouvreOptions[K]) => {
    setOptions((old) => ({ ...old, [key]: value }));
  };

  const onFile = (event: ChangeEvent<HTMLInputElement>) => {
    const nextFile = event.target.files?.[0];
    if (!nextFile) return;
    if (sourceUrl) URL.revokeObjectURL(sourceUrl);
    setFile(nextFile);
    setSourceUrl(URL.createObjectURL(nextFile));
    setResultUrl('');
    setError('');
  };

  const generate = async () => {
    if (!file) {
      setError('请先上传图片');
      return;
    }
    const form = new FormData();
    form.set('image', file);
    form.set('threshold', String(options.threshold));
    form.set('blur_radius', String(options.blurRadius));
    form.set('line_weight', String(options.lineWeight));
    form.set('max_size', String(options.maxSize));
    form.set('background', options.background);
    form.set('from_color', options.fromColor);
    form.set('to_color', options.toColor);
    form.set('direction', options.direction);
    form.set('invert', String(options.invert));

    setBusy(true);
    setError('');
    try {
      const res = await apiForm<{ image: string; filename: string; size: number }>('/api/louvre/generate', form);
      setResultUrl(res.image);
    } catch (err) {
      setError(err instanceof Error ? err.message : '生成失败');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="page-section louvre-page">
      <div className="section-head">
        <div>
          <p className="eyebrow">LOUVRE GENERATOR</p>
          <h2>卢浮宫生成器</h2>
        </div>
      </div>
      {error && <div className="error-box">{error}</div>}
      <div className="louvre-layout">
        <aside className="louvre-controls">
          <label>
            上传图片
            <input type="file" accept="image/*" onChange={onFile} />
          </label>
          <label>
            线条阈值：{options.threshold}
            <input type="range" min="4" max="90" value={options.threshold} onChange={(e) => updateOption('threshold', Number(e.target.value))} />
          </label>
          <label>
            平滑半径：{options.blurRadius}
            <input type="range" min="0" max="5" value={options.blurRadius} onChange={(e) => updateOption('blurRadius', Number(e.target.value))} />
          </label>
          <label>
            线稿粗细：{options.lineWeight}
            <input type="range" min="1" max="5" value={options.lineWeight} onChange={(e) => updateOption('lineWeight', Number(e.target.value))} />
          </label>
          <label>
            输出尺寸：{options.maxSize}px
            <input type="range" min="360" max="1400" step="20" value={options.maxSize} onChange={(e) => updateOption('maxSize', Number(e.target.value))} />
          </label>
          <div className="color-row">
            <label>
              起始颜色
              <input type="color" value={options.fromColor} onChange={(e) => updateOption('fromColor', e.target.value)} />
            </label>
            <label>
              结束颜色
              <input type="color" value={options.toColor} onChange={(e) => updateOption('toColor', e.target.value)} />
            </label>
            <label>
              背景颜色
              <input type="color" value={options.background} onChange={(e) => updateOption('background', e.target.value)} />
            </label>
          </div>
          <label>
            渐变方向
            <select value={options.direction} onChange={(e) => updateOption('direction', e.target.value as LouvreOptions['direction'])}>
              <option value="vertical">纵向</option>
              <option value="horizontal">横向</option>
              <option value="diagonal">斜向</option>
            </select>
          </label>
          <label className="check-row">
            <input type="checkbox" checked={options.invert} onChange={(e) => updateOption('invert', e.target.checked)} />
            反相线条
          </label>
          <button onClick={generate} disabled={busy || !file}>
            {busy ? '生成中...' : resultUrl ? '重新生成' : '生成线稿'}
          </button>
          {resultUrl && (
            <a className="download-button" href={resultUrl} download="louvre-line-art.png">
              下载 PNG
            </a>
          )}
        </aside>
        <div className="louvre-preview">
          {!sourceUrl && !resultUrl && (
            <div className="upload-empty">
              <Sparkles size={44} />
              <p>选择一张图片开始生成。</p>
            </div>
          )}
          {sourceUrl && !resultUrl && <img className="source-preview" src={sourceUrl} alt="source" />}
          {resultUrl && <img className="result-preview" src={resultUrl} alt="generated louvre line art" />}
        </div>
      </div>
    </section>
  );
}

function RuleLabModal({ onClose }: { onClose: () => void }) {
  const defaultCode = [
    'items = []',
    'for item in iter_preview_items():',
    '    items.append(item)',
    'result = {"user": user["username"], "items": items}'
  ].join('\n');
  const [code, setCode] = useState(defaultCode);
  const [running, setRunning] = useState(false);
  const [output, setOutput] = useState('');
  const [error, setError] = useState('');

  const run = async () => {
    setRunning(true);
    setOutput('');
    setError('');
    try {
      const res = await api<{ ok: boolean; result?: unknown; error?: string; elapsedMs?: number }>('/api/rules/run', {
        method: 'POST',
        body: JSON.stringify({ code })
      });
      if (res.ok) {
        setOutput(`result = ${JSON.stringify(res.result, null, 2)}\nelapsed = ${res.elapsedMs}ms`);
      } else {
        setError(`${res.error ?? 'rule failed'} (${res.elapsedMs ?? 0}ms)`);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : '运行失败');
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="modal-backdrop">
      <section className="rule-lab-modal">
        <header>
          <div>
            <p className="eyebrow">RULE LAB</p>
            <h3>规则测试台</h3>
            <p>客服后台用于临时验证优惠、退款和发货预览规则。脚本需要把最终输出赋值给 result。</p>
          </div>
          <button onClick={onClose}>关闭</button>
        </header>
        <div className="rule-lab-panel">
          <label>
            规则脚本
            <textarea value={code} onChange={(e) => setCode(e.target.value)} spellCheck={false} />
          </label>
          <div className="rule-actions">
            <button className="primary" onClick={run} disabled={running}>
              {running ? '运行中...' : '运行'}
            </button>
          </div>
          {error && <div className="error-box">{error}</div>}
          {output && <pre className="rule-output">{output}</pre>}
        </div>
      </section>
    </div>
  );
}

function FloatingBot({ user, refreshUser }: { user: User; refreshUser: (user: User) => void }) {
  const [chatOpen, setChatOpen] = useState(false);
  const [configOpen, setConfigOpen] = useState(false);
  const [ruleLabOpen, setRuleLabOpen] = useState(false);
  const [botState, setBotState] = useState<BotState>('normal');
  const image = useMemo(() => `/bot_imgs/${botState}.png`, [botState]);
  const isSupportAdmin = user.role === 'support_admin';

  return (
    <>
      <div className="floating-bot">
        <div className="bot-actions">
          {isSupportAdmin && (
            <button onClick={() => setRuleLabOpen(true)} title="规则测试台">
              <Wrench size={18} />
            </button>
          )}
          <button onClick={() => setConfigOpen(true)} title="修改配置">
            <Palette size={18} />
          </button>
          <button onClick={() => setChatOpen(true)} title="聊天">
            <MessageCircle size={18} />
          </button>
        </div>
        <img src={image} alt="bot" />
      </div>
      {chatOpen && (
        <BotChatModal
          botState={botState}
          setBotState={setBotState}
          refreshUser={refreshUser}
          openRuleLab={() => setRuleLabOpen(true)}
          onClose={() => setChatOpen(false)}
        />
      )}
      {configOpen && <ConfigModal onClose={() => setConfigOpen(false)} />}
      {ruleLabOpen && <RuleLabModal onClose={() => setRuleLabOpen(false)} />}
    </>
  );
}

function BotChatModal({
  botState,
  setBotState,
  refreshUser,
  openRuleLab,
  onClose
}: {
  botState: BotState;
  setBotState: (state: BotState) => void;
  refreshUser: (user: User) => void;
  openRuleLab: () => void;
  onClose: () => void;
}) {
  const [message, setMessage] = useState('/help');
  const [log, setLog] = useState<{ from: 'user' | 'bot'; text: string }[]>([]);
  const [busy, setBusy] = useState(false);
  const logRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight, behavior: 'smooth' });
  }, [log]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!message.trim() || busy) return;
    const outgoing = message.trim();
    setLog((old) => [...old, { from: 'user', text: outgoing }]);
    setMessage('');
    setBusy(true);
    setBotState('thinking');
    try {
      const res = await api<{ reply: string; data?: { user?: User; action?: string } }>('/api/bot/chat', {
        method: 'POST',
        body: JSON.stringify({ message: outgoing })
      });
      setLog((old) => [...old, { from: 'bot', text: res.reply }]);
      if (res.data?.user) refreshUser(res.data.user);
      if (res.data?.action === 'open_rule_lab') openRuleLab();
      setBotState('complete');
      window.setTimeout(() => setBotState('normal'), 5000);
    } catch (err) {
      setLog((old) => [...old, { from: 'bot', text: err instanceof Error ? err.message : '请求失败' }]);
      setBotState('normal');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="modal-backdrop bot-backdrop">
      <section className="chat-modal bot-dialog-shell">
        <button className="bot-close" onClick={onClose} aria-label="关闭">
          x
        </button>
        <div className="bot-stage">
          <img className="bot-portrait" src={`/bot_imgs/${botState}.png`} alt="bot" />
          <span className="bot-state-chip">{botState === 'thinking' ? '处理中' : botState === 'complete' ? '完成' : '空闲'}</span>
        </div>
        <div className="bot-terminal">
          <div className="chat-log" ref={logRef}>
            {log.length === 0 && <p className="empty-log">输入 /help 查看可用命令。</p>}
            {log.map((item, index) => (
              <div key={`${item.from}-${index}`} className={`bubble ${item.from}`}>
                {item.text}
              </div>
            ))}
          </div>
          <form onSubmit={submit} className="chat-input">
            <input value={message} onChange={(e) => setMessage(e.target.value)} placeholder="/help" />
            <button disabled={busy}>{busy ? '...' : '发送'}</button>
          </form>
        </div>
      </section>
    </div>
  );
}

function ConfigModal({ onClose }: { onClose: () => void }) {
  const [name, setName] = useState('Mona');
  const [color, setColor] = useState('gold');
  const [saving, setSaving] = useState(false);
  const [result, setResult] = useState('');

  const save = async () => {
    setSaving(true);
    setResult('');
    try {
      const config = JSON.stringify({ name, color });
      const res = await api<{ reply: string }>('/api/bot/chat', {
        method: 'POST',
        body: JSON.stringify({ message: `/config ${config}` })
      });
      setResult(res.reply);
    } catch (err) {
      setResult(err instanceof Error ? err.message : '保存失败');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="modal-backdrop">
      <section className="config-modal">
        <header>
          <h3>Bot 配置</h3>
          <button onClick={onClose}>关闭</button>
        </header>
        <label>
          Bot 名称
          <input value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <label>
          主题颜色
          <input value={color} onChange={(e) => setColor(e.target.value)} />
        </label>
        {result && <div className="success-box">{result}</div>}
        <button onClick={save} disabled={saving}>
          {saving ? '保存中...' : '保存'}
        </button>
      </section>
    </div>
  );
}

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
