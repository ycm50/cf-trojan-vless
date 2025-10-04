
export default {
  async fetch(request, env, ctx) {
    return handleRequest(request);
  }
}
async function handleRequest(request) {
	// 创建URL对象以正确获取路径和主机名
	const url = new URL(request.url);
	const pthnm = url.pathname;
	const hostname = url.hostname;

	switch(pthnm){
		case '/':
			return new Response('加上要访问的目标',{
				status:200,
				headers:{
					'Content-Type':'text/plain; charset=utf-8'
				}
			});
		default:
			// 从路径中提取目标URL（去掉开头的斜杠）
			const targetUrl = pthnm.substring(1); // 去掉开头的斜杠

			// 验证目标URL格式是否正确
			if (!targetUrl.startsWith('http')) {
				return new Response('请提供有效的目标URL，必须以http://或https://开头', {
					status: 400,
					headers: {
						'Content-Type': 'text/plain; charset=utf-8'
					}
				});
			}

			// 创建新的请求
			const newRequest = new Request(targetUrl, {
				headers: {
					...request.headers,
					'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
					'Referer': request.url // 或根据实际需求设置
				},
				method: request.method,
				body: request.body,
				redirect: 'follow'
			});


			// 发送请求
			let response = await fetch(newRequest);

			// 获取响应内容类型
			const contentType = response.headers.get('content-type') || '';

			// 只处理HTML内容
			if (contentType.includes('text/html')) {
				// 读取响应文本
				let body = await response.text();

				// 替换相对路径的资源链接，添加目标网站的基本URL
				// 首先提取目标网站的基本URL（协议+域名）
				const targetBaseUrl = new URL(targetUrl).origin;
				// 替换相对路径链接为绝对路径
				const modifiedBody = body.replace(/(src|href)=["']\/([^"']+)/g, `$1="${targetBaseUrl}/$2`);

				// 创建新的响应
				response = new Response(modifiedBody, response);
			}

			return response;
	}
}
