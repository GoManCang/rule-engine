# applicationId
appId=100000558

# executor.timeout(S)
Rules.executor.timeout={$Rules.executor.timeout}
PreRules.executor.timeout={$PreRules.executor.timeout}

# sars monitor
sars.monitor.rest.url={$sars.monitor.rest.url}

# CRedis
CRedis.serviceUrl={$CRedis.serviceUrl}
CRedis.provider=CounterServer_03
CRedis.logging={$CRedis.logging}

# CLogging
CLogging.serverIp={$CLogging.serverIp}
CLogging.serverPort={$CLogging.serverPort}

# Data Config Server
Configs.URL={$Configs.URL}
Configs.Trace.URL={$Configs.Trace.URL}
Configs.traceLogger.URL={$Configs.traceLogger.URL}

# Counter
Counter.REST.URL.Prefix={$Counter.REST.URL.Prefix}
Counter.Venus.ipAddressList={$Counter.Venus.ipAddressList}

# DataProxy
DataProxy.REST.URL.Prefix={$DataProxy.REST.URL.Prefix}
DataProxy.Venus.ipAddressList={$DataProxy.Venus.ipAddressList}
DataProxy.query.timeout = {$DataProxy.query.timeout}

# ESB
SOA.ESB.URL={$SOA.ESB.URL}

# SecLogAgent
SecLog.Agent.IP={$SecLog.Agent.IP}

# CryptoGraphy
CryptoGraphy.cscmUrl={$CryptoGraphy.cscmUrl}
CryptoGraphy.sslcode={$CryptoGraphy.sslcode}
CryptoGraphy.dependency.env={$CryptoGraphy.dependency.env}

# RabbitMQ
rabbitmq.inner.host={$rabbitmq.inner.host}
rabbitmq.inner.vhost={$rabbitmq.inner.vhost}
rabbitmq.inner.username={$rabbitmq.inner.username}
rabbitmq.inner.password={$rabbitmq.inner.password}

# Venus
venus.server.binding.port=16800
venus.server.manager.executor.size=64
venus.socket.receiveBufferSize=64
venus.socket.sendBufferSize=64

#RService
RService.Ip={$RService.Ip}

# RiskFact persistence config
reqId.allInOne.name = {$reqId.allInOne.name}
reqId.table.name = {$reqId.table.name}
reqId.column.name = {$reqId.column.name}