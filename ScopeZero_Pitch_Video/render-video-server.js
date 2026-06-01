import http from "node:http";
import { createReadStream, promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.PORT || 8799);

const server = http.createServer(async (req, res) => {
  const requestUrl = new URL(req.url, `http://${req.headers.host || "127.0.0.1"}`);

  if (req.method === "POST" && requestUrl.pathname === "/upload") {
    const requestedFile = requestUrl.searchParams.get("file") || "scopezero-pitch-video.webm";
    const safeFile = path.basename(requestedFile).replace(/[^a-z0-9._-]/gi, "");
    const output = path.join(__dirname, safeFile || "scopezero-pitch-video.webm");
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", async () => {
      await fs.writeFile(output, Buffer.concat(chunks));
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("saved");
      console.log(`saved ${output}`);
      setTimeout(() => server.close(() => process.exit(0)), 350);
    });
    return;
  }

  const pathname = requestUrl.pathname === "/" ? "/pitch-video.html" : requestUrl.pathname;
  const file = path.join(__dirname, pathname);
  if (!file.startsWith(__dirname)) {
    res.writeHead(403);
    res.end("forbidden");
    return;
  }

  try {
    await fs.access(file);
    const ext = path.extname(file).toLowerCase();
    const contentType = {
      ".html": "text/html; charset=utf-8",
      ".js": "text/javascript; charset=utf-8",
      ".css": "text/css; charset=utf-8",
      ".m4a": "audio/mp4",
      ".wav": "audio/wav",
      ".aiff": "audio/aiff",
      ".webm": "video/webm",
      ".mp4": "video/mp4"
    }[ext] || "application/octet-stream";
    res.writeHead(200, { "content-type": contentType });
    createReadStream(file).pipe(res);
  } catch {
    res.writeHead(404);
    res.end("not found");
  }
});

server.listen(port, "127.0.0.1", () => {
  console.log(`recording server listening at http://127.0.0.1:${port}/`);
});
