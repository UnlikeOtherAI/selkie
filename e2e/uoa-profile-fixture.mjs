// Disposable UOA API fixture: profiles stay behind a real HTTP API, never JWT/SQL.
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
const bearer = createHash('sha256').update('localhoste2e-uoa-secret').digest('hex');
const server = createServer((request, response) => {
  const url = new URL(request.url, 'http://localhost');
  if (request.headers.authorization !== `Bearer ${bearer}` || url.pathname !== '/domain/users'
      || url.searchParams.get('domain') !== 'localhost') {
    response.writeHead(403).end(); return;
  }
  const users = url.searchParams.get('user_id') === 'dev-agent-smith' ? [{
    id: 'dev-agent-smith', name: 'Agent Smith', email: 'agent.smith@dev.local',
    avatar_url: 'https://api.dicebear.com/9.x/bottts/svg?seed=AgentSmith',
  }] : [];
  response.setHeader('Content-Type', 'application/json');
  response.end(JSON.stringify({ ok: true, users }));
});
server.listen(Number(process.env.FIXTURE_PORT), '127.0.0.1');
process.on('SIGTERM', () => server.close(() => process.exit(0)));
