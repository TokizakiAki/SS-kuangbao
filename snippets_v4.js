import { connect } from 'cloudflare:sockets';

// ============ 预编译常量 ============
const UUID = new Uint8Array([
  0x55, 0xd9, 0xec, 0x38, 0x1b, 0x8a, 0x45, 0x4b,
  0x98, 0x1a, 0x6a, 0xcf, 0xe8, 0xf5, 0x6d, 0x8c
]);
const PROXY_HOST = 'sjc.o00o.ooo';
const PROXY_PORT = 443;

// 地址类型
const ATYPE_IPV4 = 1;
const ATYPE_DOMAIN = 2;
const ATYPE_IPV6 = 3;

// 流控配置
const WS_HIGH_WATER = 65536;   // 64KB 背压阈值
const WS_BACKOFF_MS = 5;       // 背压等待间隔
const CONNECT_TIMEOUT = 1000;  // 1秒连接超时

// ============ 单例复用 ============
const textDecoder = new TextDecoder();
const EMPTY_BYTES = new Uint8Array(0);

// ============ 类型稳定的返回对象工厂 ============
const createParseResult = (host, end, ok) => ({ host, end, ok });
const createDecodeResult = (data, ok) => ({ data, ok });

// 预分配错误对象 - 避免重复创建
const PARSE_FAIL = Object.freeze(createParseResult('', 0, false));
const DECODE_FAIL = Object.freeze(createDecodeResult(null, false));

// ============ 预编译响应配置 ============
const RESP_101 = (ws) => new Response(null, { status: 101, webSocket: ws });
const RESP_400 = () => new Response(null, { status: 400 });
const RESP_403 = () => new Response(null, { status: 403 });
const RESP_426 = () => new Response(null, { status: 426, headers: { Upgrade: 'websocket' } });
const RESP_502 = () => new Response(null, { status: 502 });

// ============ Base64 URL-safe 解码 ============
const decodeBase64 = (str) => {
  try {
    const binary = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
    const len = binary.length;
    const arr = new Uint8Array(len);
    // 4字节展开循环
    const end4 = len & ~3;
    let i = 0;
    for (; i < end4; i += 4) {
      arr[i] = binary.charCodeAt(i);
      arr[i + 1] = binary.charCodeAt(i + 1);
      arr[i + 2] = binary.charCodeAt(i + 2);
      arr[i + 3] = binary.charCodeAt(i + 3);
    }
    for (; i < len; i++) {
      arr[i] = binary.charCodeAt(i);
    }
    return createDecodeResult(arr, true);
  } catch {
    return DECODE_FAIL;
  }
};

// ============ UUID 验证（位运算合并比较） ============
const verifyUUID = (data) => (
  ((data[1] ^ UUID[0]) | (data[2] ^ UUID[1]) | (data[3] ^ UUID[2]) | (data[4] ^ UUID[3]) |
   (data[5] ^ UUID[4]) | (data[6] ^ UUID[5]) | (data[7] ^ UUID[6]) | (data[8] ^ UUID[7]) |
   (data[9] ^ UUID[8]) | (data[10] ^ UUID[9]) | (data[11] ^ UUID[10]) | (data[12] ^ UUID[11]) |
   (data[13] ^ UUID[12]) | (data[14] ^ UUID[13]) | (data[15] ^ UUID[14]) | (data[16] ^ UUID[15])) === 0
);

// ============ 地址解析 ============
const parseAddress = (data, offset) => {
  const atype = data[offset + 3];
  const base = offset + 4;
  const dataLen = data.length;

  if (atype === ATYPE_DOMAIN) {
    const domainLen = data[base];
    const end = base + 1 + domainLen;
    if (end > dataLen) return PARSE_FAIL;
    return createParseResult(
      textDecoder.decode(data.subarray(base + 1, end)),
      end,
      true
    );
  }

  if (atype === ATYPE_IPV4) {
    const end = base + 4;
    if (end > dataLen) return PARSE_FAIL;
    return createParseResult(
      `${data[base]}.${data[base + 1]}.${data[base + 2]}.${data[base + 3]}`,
      end,
      true
    );
  }

  if (atype === ATYPE_IPV6) {
    const end = base + 16;
    if (end > dataLen) return PARSE_FAIL;
    const dv = new DataView(data.buffer, data.byteOffset + base, 16);
    return createParseResult(
      `${dv.getUint16(0).toString(16)}:${dv.getUint16(2).toString(16)}:` +
      `${dv.getUint16(4).toString(16)}:${dv.getUint16(6).toString(16)}:` +
      `${dv.getUint16(8).toString(16)}:${dv.getUint16(10).toString(16)}:` +
      `${dv.getUint16(12).toString(16)}:${dv.getUint16(14).toString(16)}`,
      end,
      true
    );
  }

  return PARSE_FAIL;
};

// ============ 超时控制 ============
const withTimeout = (promise, ms) => {
  let tid;
  return Promise.race([
    promise,
    new Promise((_, rej) => { tid = setTimeout(() => rej(new Error('timeout')), ms); })
  ]).finally(() => clearTimeout(tid));
};

// ============ TCP 连接 ============
const connectTCP = async (host, port, fallback) => {
  const socket = connect(
    { hostname: fallback ? PROXY_HOST : host, port: fallback ? PROXY_PORT : port },
    { allowHalfOpen: false }
  );
  await withTimeout(socket.opened, CONNECT_TIMEOUT);
  return socket;
};

// ============ 连接状态（固定形状） ============
class State {
  constructor() {
    this.closed = false;
    this.ws = null;
    this.tcp = null;
  }

  init(ws, tcp) {
    this.ws = ws;
    this.tcp = tcp;
  }

  shutdown() {
    if (this.closed) return;
    this.closed = true;
    try { this.ws?.close(); } catch {}
    try { this.tcp?.close(); } catch {}
  }
}

// ============ 首帧构建 ============
const buildFirstFrame = (chunk) => {
  const frame = new Uint8Array(chunk.length + 2);
  frame.set(chunk, 2);
  return frame;
};

// ============ 上行管道（WebSocket → TCP） ============
const createUplink = (state, initial, writable) => {
  const writer = writable.getWriter();
  let chain = Promise.resolve();

  const write = (chunk) => {
    chain = chain
      .then(() => state.closed ? undefined : writer.write(chunk))
      .catch(() => state.shutdown());
  };

  if (initial.length > 0) write(initial);

  return (ev) => {
    if (!state.closed) write(new Uint8Array(ev.data));
  };
};

// ============ 下行管道（TCP → WebSocket） ============
const createDownlink = (state, ws, readable) => {
  const reader = readable.getReader();
  let first = true;

  (async () => {
    try {
      while (!state.closed) {
        // 背压控制
        while (ws.bufferedAmount > WS_HIGH_WATER && !state.closed) {
          await new Promise(r => setTimeout(r, WS_BACKOFF_MS));
        }
        if (state.closed) break;

        const { done, value } = await reader.read();
        if (done || state.closed) break;

        ws.send(first ? (first = false, buildFirstFrame(value)) : value);
      }
    } catch {
      // 连接异常
    } finally {
      state.shutdown();
      try { reader.releaseLock(); } catch {}
    }
  })();
};

// ============ 主处理器 ============
export default {
  async fetch(req) {
    // 快速路径检查
    if (req.headers.get('Upgrade') !== 'websocket') return RESP_426();

    const protocol = req.headers.get('Sec-WebSocket-Protocol');
    if (!protocol) return RESP_400();

    // 解码 payload
    const decoded = decodeBase64(protocol);
    if (!decoded.ok || decoded.data.length < 18) return RESP_400();
    const data = decoded.data;

    // UUID 验证
    if (!verifyUUID(data)) return RESP_403();

    // 地址偏移与端口
    const addrOffset = 18 + data[17];
    if (addrOffset + 4 > data.length) return RESP_400();
    const port = (data[addrOffset + 1] << 8) | data[addrOffset + 2];

    // 解析地址
    const addr = parseAddress(data, addrOffset);
    if (!addr.ok) return RESP_400();

    // TCP 连接（回退机制）
    let tcp;
    try {
      tcp = await connectTCP(addr.host, port, false);
    } catch {
      try {
        tcp = await connectTCP(addr.host, port, true);
      } catch {
        return RESP_502();
      }
    }

    // WebSocket 握手
    const [client, server] = Object.values(new WebSocketPair());
    server.accept();

    // 初始化状态
    const state = new State();
    state.init(server, tcp);

    // 初始数据
    const initial = data.length > addr.end ? data.subarray(addr.end) : EMPTY_BYTES;

    // 建立管道
    const onMessage = createUplink(state, initial, tcp.writable);
    server.addEventListener('message', onMessage);
    server.addEventListener('close', () => state.shutdown());
    server.addEventListener('error', () => state.shutdown());
    createDownlink(state, server, tcp.readable);

    return RESP_101(client);
  }
};
