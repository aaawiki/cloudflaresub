// REALITY 节点回环测试：vless+reality 解析 → Clash YAML / Raw 输出参数不丢失
import assert from 'node:assert/strict';
import worker from '../src/worker.js';

const store = new Map();
const env = {
  SUB_STORE: {
    get: async (k) => store.get(k) ?? null,
    put: async (k, v) => store.set(k, v),
  },
};

const realityVless =
  'vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?' +
  'type=tcp&security=reality&pbk=xReB0nN3DemoPublicKey&sid=a1b2c3d4' +
  '&sni=www.example.com&fp=chrome&flow=xtls-rprx-vision#reality-demo';

const req = new Request('https://sub.example.com/api/generate', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ nodeLinks: realityVless, preferredIps: '' }),
});
const res = await worker.fetch(req, env);
const data = await res.json();
assert.equal(data.ok, true, '生成失败');
assert.equal(data.counts.outputNodes, 1);

const preview = data.preview[0];
assert.equal(preview.type, 'vless');
assert.equal(preview.sni, 'www.example.com');

const clash = await (await worker.fetch(new Request(data.urls.clash), env)).text();
assert.match(clash, /type: vless/);
assert.match(clash, /tls: true/);
assert.match(clash, /flow: xtls-rprx-vision/);
assert.match(clash, /client-fingerprint: chrome/);
assert.match(clash, /reality-opts:/);
assert.match(clash, /public-key: "xReB0nN3DemoPublicKey"/);
assert.match(clash, /short-id: "a1b2c3d4"/);
assert.match(clash, /servername: "www\.example\.com"/);

const raw = await (await worker.fetch(new Request(data.urls.raw), env)).text();
const decoded = Buffer.from(raw, 'base64').toString();
assert.match(decoded, /security=reality/);
assert.match(decoded, /pbk=xReB0nN3DemoPublicKey/);
assert.match(decoded, /sid=a1b2c3d4/);
assert.match(decoded, /flow=xtls-rprx-vision/);
assert.match(decoded, /fp=chrome/);

// 优选 IP 替换后 reality 参数同样保留
const req2 = new Request('https://sub.example.com/api/generate', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ nodeLinks: realityVless, preferredIps: '104.16.1.2#HK' }),
});
const data2 = await (await worker.fetch(req2, env)).json();
assert.equal(data2.counts.outputNodes, 1);
const clash2 = await (await worker.fetch(new Request(data2.urls.clash), env)).text();
assert.match(clash2, /server: 104\.16\.1\.2/);
assert.match(clash2, /reality-opts:/);
assert.match(clash2, /servername: "www\.example\.com"/);

console.log('reality round-trip test passed');
