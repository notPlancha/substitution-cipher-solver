const PORT = Number(process.env.PORT) || 3000;

const server = Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url);
    let pathname = url.pathname;
    if (pathname === "/") pathname = "/index.html";

    const filePath = `.${pathname}`;
    const file = Bun.file(filePath);

    if (await file.exists()) {
      return new Response(file);
    }
    return new Response("Not Found", { status: 404 });
  },
});

console.log(`Substitution Cipher Solver running at: http://localhost:${server.port}`);
