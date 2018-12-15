1.sock4,sock5是基于socket层的代理，在这一层http,https协议对我们来说均是数据，我们不关心其格式。
2.shadowsocket需要浏览器配合，将http,https在自socket向外扔时，扔给socket5,这样shadowsocket就可处理了。
3.shadowsocket的local是一个sock5的server,收到报文后，加密扔给远端即server
4.server收到报文后，解开报文，创建能连接到请求对应的目地地址的socket,再把数据扔给这个socket.
5.反向数据自4,3,2,1反向流回。

故：1.sock5需要解决告知被代理方，应连接谁？即地址协商阶段要完成的工作。
