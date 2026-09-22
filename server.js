const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { spawn, execFile } = require('child_process');

const ROOT = __dirname;
const PORT = Number(process.env.PORT || 4173);
const executable = path.join(ROOT, 'checker.exe');
const gpuExecutable = path.join(ROOT, 'checker_gpu.exe');
const jobs = new Map();
const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };

function json(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(body));
}

function send(job, event, data) {
  const message = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  job.events.push(message);
  job.clients.forEach((client) => client.write(message));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > 8 * 1024 * 1024) req.destroy();
    });
    req.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); } catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}

function validHash(value) {
  return typeof value === 'string' && /^[a-fA-F0-9]{64}$/.test(value);
}

function validCharset(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 64 && !/[\x00\r\n]/.test(value);
}

function validRuntime(value) {
  return value === 'cpu' || value === 'gpu';
}

function listGpuDevices() {
  return new Promise((resolve) => {
    if (!fs.existsSync(gpuExecutable)) return resolve({ error: 'checker_gpu.exe is missing. Run npm run build first.', devices: [] });
    const child = spawn(gpuExecutable, ['list'], { cwd: ROOT, windowsHide: true });
    let output = '';
    let errorOutput = '';
    const devices = [];
    child.stdout.on('data', (chunk) => { output += chunk.toString('utf8'); });
    child.stderr.on('data', (chunk) => { errorOutput += chunk.toString('utf8'); });
    child.on('error', (error) => resolve({ error: error.message, devices: [] }));
    child.on('close', () => {
      let sawError = null;
      output.split(/\r?\n/).filter(Boolean).forEach((line) => {
        let match = line.match(/^DEVICE\s+(\d+)\s+(\S+)\s+(.*?)\s+CU:(\d+)\s+CLOCK:(\d+)\s+MEM:(\d+)/);
        if (match) {
          devices.push({ index: Number(match[1]), type: match[2], name: match[3], computeUnits: Number(match[4]), clockMHz: Number(match[5]), memoryMB: Number(match[6]) });
          return;
        }
        match = line.match(/^ERROR\s*(.*)$/);
        if (match) sawError = match[1] || 'GPU device detection failed.';
      });
      if (!devices.length && !sawError) sawError = errorOutput.trim() || 'No OpenCL devices found.';
      resolve({ error: devices.length ? null : sawError, devices });
    });
  });
}

function finish(job, result) {
  if (job.finished) return;
  job.finished = true;
  send(job, 'result', result);
  job.clients.forEach((client) => client.end());
  if (job.tempWordlist) fs.rm(job.tempWordlist, { force: true }, () => {});
  setTimeout(() => jobs.delete(job.id), 5 * 60 * 1000).unref();
}

function startJob(options) {
  const id = crypto.randomUUID();
  const runtime = options.runtime === 'gpu' ? 'gpu' : 'cpu';
  const chosenExecutable = runtime === 'gpu' ? gpuExecutable : executable;
  const args = options.mode === 'wordlist'
    ? ['wordlist', options.hash, options.tempWordlist]
    : runtime === 'gpu'
      ? ['brute', options.hash, options.charset, String(options.minLength), String(options.maxLength), String(options.device)]
      : ['brute', options.hash, options.charset, String(options.minLength), String(options.maxLength)];
  const job = { id, clients: new Set(), events: [], workers: new Map(), count: 0, lastProgressSent: 0, startedAt: Date.now(), finished: false, tempWordlist: options.tempWordlist };
  jobs.set(id, job);
  const child = spawn(chosenExecutable, args, { cwd: ROOT, windowsHide: true });
  job.child = child;
  let output = '';
  const consume = (chunk) => {
    output += chunk.toString('utf8');
    const lines = output.split(/\r?\n/);
    output = lines.pop();
    lines.filter(Boolean).forEach((line) => {
      let match = line.match(/^PROGRESS\s+(\d+)/);
      if (match) {
        job.count = Number(match[1]);
        const now = Date.now();
        if (now - job.lastProgressSent >= 250) {
          job.lastProgressSent = now;
          send(job, 'progress', { count: job.count, elapsedMs: now - job.startedAt });
        }
        return;
      }
      match = line.match(/^WORKER\s+(\d+)\s+(\d+)/);
      if (match) {
        const workerId = Number(match[1]);
        const count = Number(match[2]);
        const now = Date.now();
        const previous = job.workers.get(workerId) || { count, time: now };
        const deltaTime = Math.max(1, now - previous.time);
        job.workers.set(workerId, { count, time: now });
        send(job, 'worker', { id: workerId, count, speed: Math.round((count - previous.count) * 1000 / deltaTime), elapsedMs: now - job.startedAt });
        return;
      }
      match = line.match(/^FOUND\s*(.*)$/);
      if (match) finish(job, { status: 'found', candidate: match[1] });
      else if (line.startsWith('ERROR')) finish(job, { status: 'error', message: 'Assembly checker could not open the wordlist or start the job.' });
      else {
        const done = line.match(/^DONE\s*(\d+)?/);
        if (done) {
          if (done[1]) job.count = Number(done[1]);
          finish(job, { status: 'done', count: job.count });
        }
      }
    });
  };
  child.stdout.on('data', consume);
  child.stderr.on('data', (chunk) => send(job, 'log', { message: chunk.toString('utf8') }));
  child.on('error', (error) => finish(job, { status: 'error', message: error.message }));
  child.on('close', (code) => {
    if (!job.finished) finish(job, { status: code === 0 ? 'done' : 'error', count: job.count, code });
  });
  return id;
}

function serveStatic(req, res) {
  const requested = req.url === '/' ? '/index.html' : req.url.split('?')[0];
  const file = path.resolve(ROOT, 'public', `.${requested}`);
  if (!file.startsWith(path.resolve(ROOT, 'public'))) return json(res, 403, { error: 'Forbidden' });
  fs.readFile(file, (error, data) => {
    if (error) return json(res, 404, { error: 'Not found' });
    res.writeHead(200, { 'Content-Type': mime[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'POST' && req.url === '/api/start') {
      const body = await readBody(req);
      if (!validHash(body.hash)) return json(res, 400, { error: 'Enter a 64-character SHA-256 hash.' });
      const runtime = validRuntime(body.runtime) ? body.runtime : 'cpu';
      body.runtime = runtime;
      if (runtime === 'gpu' && body.mode === 'wordlist') return json(res, 400, { error: 'The GPU engine only supports brute-force mode.' });
      if (body.mode === 'wordlist') {
        if (typeof body.wordlistName !== 'string' || typeof body.wordlistContent !== 'string' || body.wordlistContent.length > 8 * 1024 * 1024) return json(res, 400, { error: 'Choose a wordlist smaller than 6 MiB.' });
        const tempWordlist = path.join(os.tmpdir(), `hashforge-${crypto.randomUUID()}.txt`);
        fs.writeFileSync(tempWordlist, Buffer.from(body.wordlistContent, 'base64'));
        body.tempWordlist = tempWordlist;
      } else if (body.mode === 'brute' && validCharset(body.charset) && Number.isInteger(body.minLength) && Number.isInteger(body.maxLength) && body.minLength > 0 && body.maxLength >= body.minLength && body.maxLength <= 12) {
        if (runtime === 'gpu' && !(Number.isInteger(body.device) && body.device >= 0)) return json(res, 400, { error: 'Choose a GPU device.' });
      } else return json(res, 400, { error: 'Choose a valid cracking mode and range.' });
      const chosenExecutable = runtime === 'gpu' ? gpuExecutable : executable;
      const missingName = runtime === 'gpu' ? 'checker_gpu.exe' : 'checker.exe';
      if (!fs.existsSync(chosenExecutable)) return json(res, 500, { error: `${missingName} is missing. Run npm run build first.` });
      return json(res, 200, { id: startJob(body) });
    }
    if (req.method === 'GET' && req.url === '/api/devices') {
      const result = await listGpuDevices();
      return json(res, 200, result);
    }
    if (req.method === 'GET' && req.url.startsWith('/api/events/')) {
      const id = req.url.slice('/api/events/'.length);
      const job = jobs.get(id);
      if (!job) return json(res, 404, { error: 'Job not found or already finished.' });
      res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
      res.write('retry: 1000\n\n');
      job.events.forEach((message) => res.write(message));
      if (job.finished) return res.end();
      job.clients.add(res);
      req.on('close', () => job.clients.delete(res));
      return;
    }
    if (req.method === 'POST' && req.url.startsWith('/api/stop/')) {
      const job = jobs.get(req.url.slice('/api/stop/'.length));
      if (job && job.child) {
        if (process.platform === 'win32') execFile('taskkill', ['/pid', String(job.child.pid), '/t', '/f'], () => {});
        else job.child.kill('SIGTERM');
      }
      return json(res, 200, { ok: true });
    }
    serveStatic(req, res);
  } catch (error) { json(res, 400, { error: error.message }); }
});

function listen(port) {
  const onError = (error) => {
    server.removeListener('error', onError);
    if (error.code === 'EADDRINUSE' && port < PORT + 20) return listen(port + 1);
    throw error;
  };
  server.once('error', onError);
  server.listen(port, '127.0.0.1', () => console.log(`ASM cracker GUI: http://127.0.0.1:${port}`));
}

listen(PORT);