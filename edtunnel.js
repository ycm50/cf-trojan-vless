var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/w.js
import { connect } from "cloudflare:sockets";
var IDu = "cc1a420a-54ba-4607-a0dd-afb9195b909f";
var pxxIPs = [];
var pxxIP = pxxIPs[Math.floor(Math.random() * pxxIPs.length)];
var pxxPort = pxxIP && pxxIP.includes(":") ? pxxIP.split(":")[1] : "443";
var skk5Address = "";
var skk5Relay = false;
if (!isValidUUID(IDu)) {
  throw new Error("uuid is not valid");
}
var parsedskk5Address = {};
var enableskk = false;
var w_default = {
  /**
   * @param {import("@cloudflare/workers-types").Request} request
   * @param {{UUID: string, pxxIP: string, skk5: string, skk5_RELAY: string}} env
   * @param {import("@cloudflare/workers-types").ExecutionContext} _ctx
   * @returns {Promise<Response>}
   */
  async fetch(request, env, _ctx) {
    try {
      const { UUID, pxxIP: pxxIP2, skk5, skk5_RELAY } = env;
      const url = new URL(request.url);
      const requestConfig = {
        IDu: UUID || IDu,
        skk5Address: skk5 || skk5Address,
        skk5Relay: skk5_RELAY === "true" || skk5Relay,
        pxxIP: null,
        pxxPort: null,
        enableskk: false,
        parsedskk5Address: {}
      };
      let urlpxxIP = url.searchParams.get("pxxip");
      let urlskk5 = url.searchParams.get("skk5");
      let urlskk5_RELAY = url.searchParams.get("skk5_relay");
      if (!urlpxxIP && !urlskk5 && !urlskk5_RELAY) {
        const encodedParams = parseEncodedQueryParams(url.pathname);
        urlpxxIP = urlpxxIP || encodedParams.pxxip;
        urlskk5 = urlskk5 || encodedParams.skk5;
        urlskk5_RELAY = urlskk5_RELAY || encodedParams.skk5_relay;
      }
      if (urlpxxIP) {
        const pxxPattern = /^([a-zA-Z0-9][-a-zA-Z0-9.]*(\.[a-zA-Z0-9][-a-zA-Z0-9.]*)+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[[0-9a-fA-F:]+\]):\d{1,5}$/;
        const pxxAddresses = urlpxxIP.split(",").map((addr) => addr.trim());
        const isValid = pxxAddresses.every((addr) => pxxPattern.test(addr));
        if (!isValid) {
          console.warn("\u65E0\u6548\u7684pxxip\u683C\u5F0F:", urlpxxIP);
          urlpxxIP = null;
        }
      }
      if (urlskk5) {
        const skk5Pattern = /^(([^:@]+:[^:@]+@)?[a-zA-Z0-9][-a-zA-Z0-9.]*(\.[a-zA-Z0-9][-a-zA-Z0-9.]*)+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d{1,5}$/;
        const skk5Addresses = urlskk5.split(",").map((addr) => addr.trim());
        const isValid = skk5Addresses.every((addr) => skk5Pattern.test(addr));
        if (!isValid) {
          console.warn("\u65E0\u6548\u7684skk5\u683C\u5F0F:", urlskk5);
          urlskk5 = null;
        }
      }
      requestConfig.skk5Address = urlskk5 || requestConfig.skk5Address;
      requestConfig.skk5Relay = urlskk5_RELAY === "true" || requestConfig.skk5Relay;
      console.log("\u914D\u7F6E\u53C2\u6570:", requestConfig.IDu, requestConfig.skk5Address, requestConfig.skk5Relay, urlpxxIP);
      const pxxConfig = handlepxxConfig(urlpxxIP || pxxIP2);
      requestConfig.pxxIP = pxxConfig.ip;
      requestConfig.pxxPort = pxxConfig.port;
      console.log("\u4F7F\u7528\u4EE3\u7406:", requestConfig.pxxIP, requestConfig.pxxPort);
      if (requestConfig.skk5Address) {
        try {
          const selectedskk5 = selectRandomAddress(requestConfig.skk5Address);
          requestConfig.parsedskk5Address = skk5AddressParser(selectedskk5);
          requestConfig.enableskk = true;
        } catch (err) {
          console.log(err.toString());
          requestConfig.enableskk = false;
        }
      }
      const IDus = requestConfig.IDu.includes(",") ? requestConfig.IDu.split(",").map((id) => id.trim()) : [requestConfig.IDu];
      const host = request.headers.get("Host");
      const requestedPath = url.pathname.substring(1);
      const matchingIDu = IDus.length === 1 ? requestedPath === IDus[0] ? IDus[0] : null : IDus.find((id) => requestedPath === id);
      if (request.headers.get("Upgrade") !== "websocket") {
        if (url.pathname === "/cf") {
          return new Response(JSON.stringify(request.cf, null, 4), {
            status: 200,
            headers: { "Content-Type": "application/json;charset=utf-8" }
          });
        }
        if (matchingIDu) {
          if (url.pathname === `/${matchingIDu}`) {
            const pxxAddresses = pxxIP2 ? pxxIP2.split(",").map((addr) => addr.trim()) : requestConfig.pxxIP;
            const content = getConfig(matchingIDu, host, pxxAddresses);
            return new Response(content, {
              status: 200,
              headers: {
                "Content-Type": "text/html; charset=utf-8"
              }
            });
          }
        }
        return handleDefaultPath(url, request);
      } else {
        return await ProtocolOverWSHandler(request, requestConfig);
      }
    } catch (err) {
      return new Response(err.toString());
    }
  }
};
async function handleDefaultPath(url, request) {
  const host = request.headers.get("Host");
  const DrivePage = `
  <!DOCTYPE html>
  <html>
  <head>
  <title>Welcome to nginx!</title>
  <style>
    body {
      width: 35em;
      margin: 0 auto;
      font-family: Tahoma, Verdana, Arial, sans-serif;
    }
  </style>
  </head>
  <body>
  <h1>Welcome to nginx!</h1>
  <p>If you see this page, the nginx web server is successfully installed and
  working. Further configuration is required.</p>
  
  <p>For online documentation and support please refer to
  <a href="https://github.com/nginx/nginx/blob/master/README.md">nginx.org</a>.<br/>
  Commercial support is available at
  <a href="http://nginx.com/">nginx.com</a>.</p>
  
  <p><em>Thank you for using nginx.</em></p>
  </body>
  </html>
  `;
  return new Response(DrivePage, {
    headers: {
      "content-type": "text/html;charset=UTF-8"
    }
  });
}
__name(handleDefaultPath, "handleDefaultPath");
async function ProtocolOverWSHandler(request, config = null) {
  if (!config) {
    config = {
      IDu,
      skk5Address,
      skk5Relay,
      pxxIP,
      pxxPort,
      enableskk,
      parsedskk5Address
    };
  }
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();
  let address = "";
  let portWithRandomLog = "";
  const log = /* @__PURE__ */ __name((info, event) => {
    console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
  }, "log");
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = MakeReadableWebSocketStream(webSocket, earlyDataHeader, log);
  let remoteSocketWapper = {
    value: null
  };
  let isDns = false;
  readableWebSocketStream.pipeTo(new WritableStream({
    async write(chunk, controller) {
      if (isDns) {
        return await handleDNSQuery(chunk, webSocket, null, log);
      }
      if (remoteSocketWapper.value) {
        const writer = remoteSocketWapper.value.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }
      const {
        hasError,
        message,
        addressType,
        portRemote = 443,
        addressRemote = "",
        rawDataIndex,
        ProtocolVersion = new Uint8Array([0, 0]),
        isUDP
      } = ProcessProtocolHeader(chunk, config.IDu);
      address = addressRemote;
      portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? "udp " : "tcp "} `;
      if (hasError) {
        throw new Error(message);
      }
      if (isUDP) {
        if (portRemote === 53) {
          isDns = true;
        } else {
          throw new Error("UDP pxx is only enabled for DNS (port 53)");
        }
        return;
      }
      const ProtocolResponseHeader = new Uint8Array([ProtocolVersion[0], 0]);
      const rawClientData = chunk.slice(rawDataIndex);
      if (isDns) {
        return handleDNSQuery(rawClientData, webSocket, ProtocolResponseHeader, log);
      }
      HandleTCPOutBound(remoteSocketWapper, addressType, addressRemote, portRemote, rawClientData, webSocket, ProtocolResponseHeader, log, config);
    },
    close() {
      log(`readableWebSocketStream is close`);
    },
    abort(reason) {
      log(`readableWebSocketStream is abort`, JSON.stringify(reason));
    }
  })).catch((err) => {
    log("readableWebSocketStream pipeTo error", err);
  });
  return new Response(null, {
    status: 101,
    // @ts-ignore
    webSocket: client
  });
}
__name(ProtocolOverWSHandler, "ProtocolOverWSHandler");
async function HandleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, protocolResponseHeader, log, config = null) {
  if (!config) {
    config = {
      IDu,
      skk5Address,
      skk5Relay,
      pxxIP,
      pxxPort,
      enableskk,
      parsedskk5Address
    };
  }
  async function connectAndWrite(address, port, skk = false) {
    let tcpSocket2;
    if (config.skk5Relay) {
      tcpSocket2 = await skk5Connect(addressType, address, port, log, config.parsedskk5Address);
    } else {
      tcpSocket2 = skk ? await skk5Connect(addressType, address, port, log, config.parsedskk5Address) : connect({
        hostname: address,
        port
      });
    }
    remoteSocket.value = tcpSocket2;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket2.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket2;
  }
  __name(connectAndWrite, "connectAndWrite");
  async function retry() {
    let tcpSocket2;
    if (config.enableskk) {
      tcpSocket2 = await connectAndWrite(addressRemote, portRemote, true);
    } else {
      tcpSocket2 = await connectAndWrite(config.pxxIP || addressRemote, config.pxxPort || portRemote, false);
    }
    tcpSocket2.closed.catch((error) => {
      console.log("retry tcpSocket closed error", error);
    }).finally(() => {
      safeCloseWebSocket(webSocket);
    });
    RemoteSocketToWS(tcpSocket2, webSocket, protocolResponseHeader, null, log);
  }
  __name(retry, "retry");
  let tcpSocket = await connectAndWrite(addressRemote, portRemote);
  RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, retry, log);
}
__name(HandleTCPOutBound, "HandleTCPOutBound");
function MakeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        const message = event.data;
        controller.enqueue(message);
      });
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        log("webSocketServer has error");
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },
    pull(_controller) {
    },
    cancel(reason) {
      log(`ReadableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    }
  });
  return stream;
}
__name(MakeReadableWebSocketStream, "MakeReadableWebSocketStream");
function ProcessProtocolHeader(protocolBuffer, IDu2) {
  if (protocolBuffer.byteLength < 24) {
    return { hasError: true, message: "invalid data" };
  }
  const dataView = new DataView(protocolBuffer);
  const version = dataView.getUint8(0);
  const slicedBufferString = stringify(new Uint8Array(protocolBuffer.slice(1, 17)));
  const uuids = IDu2 && IDu2.includes(",") ? IDu2.split(",") : [IDu2];
  const isValidUser = uuids.some((uuid) => slicedBufferString === uuid.trim()) || uuids.length === 1 && slicedBufferString === uuids[0].trim();
  console.log(`IDu: ${slicedBufferString}`);
  if (!isValidUser) {
    return { hasError: true, message: "invalid user" };
  }
  const optLength = dataView.getUint8(17);
  const command = dataView.getUint8(18 + optLength);
  if (command !== 1 && command !== 2) {
    return { hasError: true, message: `command ${command} is not supported, command 01-tcp,02-udp,03-mux` };
  }
  const portIndex = 18 + optLength + 1;
  const portRemote = dataView.getUint16(portIndex);
  const addressType = dataView.getUint8(portIndex + 2);
  let addressValue, addressLength, addressValueIndex;
  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValueIndex = portIndex + 3;
      addressValue = new Uint8Array(protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 2:
      addressLength = dataView.getUint8(portIndex + 3);
      addressValueIndex = portIndex + 4;
      addressValue = new TextDecoder().decode(protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3:
      addressLength = 16;
      addressValueIndex = portIndex + 3;
      addressValue = Array.from({ length: 8 }, (_, i) => dataView.getUint16(addressValueIndex + i * 2).toString(16)).join(":");
      break;
    default:
      return { hasError: true, message: `invalid addressType: ${addressType}` };
  }
  if (!addressValue) {
    return { hasError: true, message: `addressValue is empty, addressType is ${addressType}` };
  }
  return {
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    protocolVersion: new Uint8Array([version]),
    isUDP: command === 2
  };
}
__name(ProcessProtocolHeader, "ProcessProtocolHeader");
async function RemoteSocketToWS(remoteSocket, webSocket, protocolResponseHeader, retry, log) {
  let hasIncomingData = false;
  try {
    await remoteSocket.readable.pipeTo(
      new WritableStream({
        async write(chunk) {
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            throw new Error("WebSocket is not open");
          }
          hasIncomingData = true;
          if (protocolResponseHeader) {
            webSocket.send(await new Blob([protocolResponseHeader, chunk]).arrayBuffer());
            protocolResponseHeader = null;
          } else {
            webSocket.send(chunk);
          }
        },
        close() {
          log(`Remote connection readable closed. Had incoming data: ${hasIncomingData}`);
        },
        abort(reason) {
          console.error(`Remote connection readable aborted:`, reason);
        }
      })
    );
  } catch (error) {
    console.error(`RemoteSocketToWS error:`, error.stack || error);
    safeCloseWebSocket(webSocket);
  }
  if (!hasIncomingData && retry) {
    log(`No incoming data, retrying`);
    await retry();
  }
}
__name(RemoteSocketToWS, "RemoteSocketToWS");
function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { earlyData: null, error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const binaryStr = atob(base64Str);
    const buffer = new ArrayBuffer(binaryStr.length);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < binaryStr.length; i++) {
      view[i] = binaryStr.charCodeAt(i);
    }
    return { earlyData: buffer, error: null };
  } catch (error) {
    return { earlyData: null, error };
  }
}
__name(base64ToArrayBuffer, "base64ToArrayBuffer");
function isValidUUID(uuid) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}
__name(isValidUUID, "isValidUUID");
var WS_READY_STATE_OPEN = 1;
var WS_READY_STATE_CLOSING = 2;
function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error("safeCloseWebSocket error:", error);
  }
}
__name(safeCloseWebSocket, "safeCloseWebSocket");
var byteToHex = Array.from({ length: 256 }, (_, i) => (i + 256).toString(16).slice(1));
function unsafeStringify(arr, offset = 0) {
  return [
    byteToHex[arr[offset]],
    byteToHex[arr[offset + 1]],
    byteToHex[arr[offset + 2]],
    byteToHex[arr[offset + 3]],
    "-",
    byteToHex[arr[offset + 4]],
    byteToHex[arr[offset + 5]],
    "-",
    byteToHex[arr[offset + 6]],
    byteToHex[arr[offset + 7]],
    "-",
    byteToHex[arr[offset + 8]],
    byteToHex[arr[offset + 9]],
    "-",
    byteToHex[arr[offset + 10]],
    byteToHex[arr[offset + 11]],
    byteToHex[arr[offset + 12]],
    byteToHex[arr[offset + 13]],
    byteToHex[arr[offset + 14]],
    byteToHex[arr[offset + 15]]
  ].join("").toLowerCase();
}
__name(unsafeStringify, "unsafeStringify");
function stringify(arr, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) {
    throw new TypeError("Stringified UUID is invalid");
  }
  return uuid;
}
__name(stringify, "stringify");
async function handleDNSQuery(udpChunk, webSocket, protocolResponseHeader, log) {
  try {
    const dnsServer = "8.8.4.4";
    const dnsPort = 53;
    let vllHeader = protocolResponseHeader;
    const tcpSocket = connect({
      hostname: dnsServer,
      port: dnsPort
    });
    log(`connected to ${dnsServer}:${dnsPort}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(udpChunk);
    writer.releaseLock();
    await tcpSocket.readable.pipeTo(new WritableStream({
      async write(chunk) {
        if (webSocket.readyState === WS_READY_STATE_OPEN) {
          if (vllHeader) {
            webSocket.send(await new Blob([vllHeader, chunk]).arrayBuffer());
            vllHeader = null;
          } else {
            webSocket.send(chunk);
          }
        }
      },
      close() {
        log(`dns server(${dnsServer}) tcp is close`);
      },
      abort(reason) {
        console.error(`dns server(${dnsServer}) tcp is abort`, reason);
      }
    }));
  } catch (error) {
    console.error(
      `handleDNSQuery have exception, error: ${error.message}`
    );
  }
}
__name(handleDNSQuery, "handleDNSQuery");
async function skk5Connect(addressType, addressRemote, portRemote, log, parsedskk5Addr = null) {
  const { username, password, hostname, port } = parsedskk5Addr || parsedskk5Address;
  const socket = connect({
    hostname,
    port
  });
  const skkGreeting = new Uint8Array([5, 2, 0, 2]);
  const writer = socket.writable.getWriter();
  await writer.write(skkGreeting);
  log("sent skk greeting");
  const reader = socket.readable.getReader();
  const encoder = new TextEncoder();
  let res = (await reader.read()).value;
  if (res[0] !== 5) {
    log(`skk server version error: ${res[0]} expected: 5`);
    return;
  }
  if (res[1] === 255) {
    log("no acceptable methods");
    return;
  }
  if (res[1] === 2) {
    log("skk server needs auth");
    if (!username || !password) {
      log("please provide username/password");
      return;
    }
    const authRequest = new Uint8Array([
      1,
      username.length,
      ...encoder.encode(username),
      password.length,
      ...encoder.encode(password)
    ]);
    await writer.write(authRequest);
    res = (await reader.read()).value;
    if (res[0] !== 1 || res[1] !== 0) {
      log("fail to auth skk server");
      return;
    }
  }
  let DSTADDR;
  switch (addressType) {
    case 1:
      DSTADDR = new Uint8Array(
        [1, ...addressRemote.split(".").map(Number)]
      );
      break;
    case 2:
      DSTADDR = new Uint8Array(
        [3, addressRemote.length, ...encoder.encode(addressRemote)]
      );
      break;
    case 3:
      DSTADDR = new Uint8Array(
        [4, ...addressRemote.split(":").flatMap((x) => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]
      );
      break;
    default:
      log(`invild  addressType is ${addressType}`);
      return;
  }
  const skkRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 255]);
  await writer.write(skkRequest);
  log("sent skk request");
  res = (await reader.read()).value;
  if (res[1] === 0) {
    log("skk connection opened");
  } else {
    log("fail to open skk connection");
    return;
  }
  writer.releaseLock();
  reader.releaseLock();
  return socket;
}
__name(skk5Connect, "skk5Connect");
function skk5AddressParser(address) {
  let [latter, former] = address.split("@").reverse();
  let username, password, hostname, port;
  if (former) {
    const formers = former.split(":");
    if (formers.length !== 2) {
      throw new Error("Invalid skk address format");
    }
    [username, password] = formers;
  }
  const latters = latter.split(":");
  port = Number(latters.pop());
  if (isNaN(port)) {
    throw new Error("Invalid skk address format");
  }
  hostname = latters.join(":");
  const regex = /^\[.*\]$/;
  if (hostname.includes(":") && !regex.test(hostname)) {
    throw new Error("Invalid skk address format");
  }
  return {
    username,
    password,
    hostname,
    port
  };
}
__name(skk5AddressParser, "skk5AddressParser");
var at = "QA==";
var pt = "dmxlc3M=";
function getConfig(IDus, hostName, pxxIP2) {
  // 配置文件生成功能已删除
  return ``;
}
__name(getConfig, "getConfig");
function handlepxxConfig(pxxIP2) {
  if (pxxIP2) {
    const pxxAddresses = pxxIP2.split(",").map((addr) => addr.trim());
    const selectedpxx = selectRandomAddress(pxxAddresses);
    const [ip, port = "443"] = selectedpxx.split(":");
    return { ip, port };
  } else {
    const port = pxxIP2 && pxxIP2.includes(":") ? pxxIP2.split(":")[1] : "443";
    const ip = pxxIP2 && pxxIP2.includes(":") ? pxxIP2.split(":")[0] : "";
    return { ip, port };
  }
}
__name(handlepxxConfig, "handlepxxConfig");
function selectRandomAddress(addresses) {
  const addressArray = typeof addresses === "string" ? addresses.split(",").map((addr) => addr.trim()) : addresses;
  return addressArray[Math.floor(Math.random() * addressArray.length)];
}
__name(selectRandomAddress, "selectRandomAddress");
function parseEncodedQueryParams(pathname) {
  const params = {};
  if (pathname.includes("%3F")) {
    const encodedParamsMatch = pathname.match(/%3F(.+)$/);
    if (encodedParamsMatch) {
      const encodedParams = encodedParamsMatch[1];
      const paramPairs = encodedParams.split("&");
      for (const pair of paramPairs) {
        const [key, value] = pair.split("=");
        if (value) params[key] = decodeURIComponent(value);
      }
    }
  }
  return params;
}
__name(parseEncodedQueryParams, "parseEncodedQueryParams");
export {
  w_default as default
};
//# sourceMappingURL=w.js.map
