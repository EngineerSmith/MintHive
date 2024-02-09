local PATH, channelIn, settings = ...

local options = require(PATH .. ".options")

local appleCake
if type(options.appleCakeLocation) == "string" and love.filesystem.getInfo(options.appleCakeLocation:gsub('%.init$', ''):gsub('%.', '/').."/init.lua", "file") then
  appleCake = require(options.appleCakeLocation)()
  appleCake.setThreadName("MintHive Server")
  appleCake.setThreadSortIndex(50)
  appleCake.setBuffer(true)
end

require("love.math") -- global module, careful usage required
local lt, le, ld = love.thread, require("love.event"), require("love.data")
local enet = require("enet")
local enum = require(PATH .. ".enum")
local serialize = require(PATH .. "serialize")

local file = love.filesystem.newFile(".data/server.dat")
file:setBuffer("none")

local POST = function(...)
  le.push(options.serverHandlerEvent, ...)
end

local getUID
do
  -- An easy security improvement here, is to use a safe cryptographic random number generator
  -- but, that requires additional setup that this library can't provide for your project
  local rand = tonumber(os.getenv("RANDOM") or 0) or 0
  local rngGen = love.math.newRandomGenerator(os.time(), 2^32-79917014+rand)
  -- override function if you wish to provide additional 'random' security
  local fill = function(byteArray, length) 
    for i = 0, length - 1 do
      byteArray[i] = rngGen:random(0, 0xFF)
    end
  end

  getUID = function()
    local salt = ld.newByteData(options.saltLength)
    fill(ffi.cast('uint8_t*', salt:getFFIPointer()), salt:getSize())
    local uid = ld.newByteData(options.uidLength)
    fill(ffi.cast('uint8_t*', uid:getFFIPointer()), uid:getSize())
    -- salt uid
    local saltedUID = ld.newByteData(uid, 0, uid:getSize() + salt:getSize())
    local offset = ld.newDataView(saltedUID, uid:getSize(), salt:getSize()):getFFIPointer()
    ffi.copy(offset, salt:getFFIPointer(), salt:getSize())
    -- hash salted uid
    local hashedUID = ld.newByteData(ld.hash(options.hashFunction, saltedUID))
    -- prepare salted uid and salt to save
    local entry = ld.newByteData(hashedUID, 0, hashedUID:getSize() + salt:getSize())
    local offset = ld.newDataView(entry, hashedUID:getSize(), salt:getSize()):getFFIPointer()
    ffi.copy(offset, salt:getFFIPointer(), salt:getSize())
    -- save entry
    local success, errmsg = file:open("a")
    if not success then
      POST("error", "Could not open uid file in append mode: "..tostring(errmsg))
      return nil, nil
    end
    file:write(entry)
    file:close()
    return uid, hashedUID
  end
end

local isExistingUID
do
  local hashSize = #ld.hash(options.hashFunction, "")
  if hashSize % 4 ~= 0 then
    -- this error should only happen, if love introduces new hash functions that aren't divisible by 4. Currently all functions are.
    POST("error", "Expected the bytes of the resulting hash size to be divisible by 4. Size: "..tostring(hashSize))
    return
  end

  isExistingUID = function(uid)
    local result, hashedUID = false, nil

    local success, errmsg = file:open("r")
    if not success then
      POST("error", "Could not open uid file in read mode: "..tostring(errmsg))
      return nil, nil
    end
    local saltedUID = ld.newByteData(uid, 0, uid:getSize() + options.saltLength)
    local saltedUID_offset = ld.newDataView(saltedUID, uid:getSize(), salt:getSize()):getFFIPointer()
    uid = nil
    while not file:isEOF() do
      -- read
      local readHash, readSize = file:read("data", hashSize)
      if not readHash or readSize ~= hashSize then break end
      local salt, readSize = file:read("data", options.saltLength)
      if not salt or readSize ~= options.saltLength then break end
      -- calculate hashed uid, with salt
      ffi.copy(saltedUID_offset, salt:getFFIPointer(), salt:getSize())
      hashedUID = ld.newByteData(ld.hash(options.hashFunction, saltedUID))
      -- compare - hash size expected to be divisible by 4
      local storedHash_ptr = ffi.cast('uint32_t*', readHash:getFFIPointer())
      local calculatedHash_ptr = ffi.cast('uint32_t*', hashedUID:getFFIPointer())

      result = true
      for i = 0, hashSize/4 - 1 do
        if storedHash_ptr[i] ~= calculatedHash_ptr[i] then
          result = false
          break
        end
      end
      if result then break end
    end
    file:close()
    return result, hashedUID 
  end
end

local clients = { }
local getClient = function(sessionID, makeNew)
  if makeNew == nil then 
    makeNew = true
  end
  local client = clients[sessionID] or (makeNew and { } or nil)
  clients[sessionID] = client
  return client
end

local removeClient = function(sessionID)
  clients[sessionID] = nil
end

local validLogin = function(client, encoded)
  local decoded = serialize.decode(encoded)
  if type(decoded) ~= "table" or decoded == nil then
    return false
  end
  -- USERNAME
  client.username = decoded.username
  if type(client.username) ~= "string"   or
     #client.username == 0               or
     client.username == "server"         or
    (options.validateUsername and not options.validateUsername(client.username))
  then
    return false
  end
  -- UID: Most expensive, so it is last in validation
  local uid
  if decoded.UID then -- existing user
    if type(decoded.UID) ~= "userdata" or decoded.UID:typeOf("Data") or decoded.UID ~= options.uidLength then
      return false
    end
    local success
    success, client.UID = isExistingUID(decoded.UID)
    decoded.UID = nil
    if not success then return false end
  else -- new user
    uid, client.UID = getUID()
  end
  --
  client.loggedIn = true
  return true, uid
end

-- thread loop

local host = enet.host_create(
  "*:"..tostring(settings.port),
  settings.maxPeers,
  enum.channelCount,
  settings.inBandwidth,
  settings.outBandwidth
)

if not host then
  return POST("error", "Could not start server on port: "..tostring(settings.port))
end

local inProfile, outProfile
while true do
  -- RECEIVE
  inProfile = appleCake and appleCake.isActive and appleCake.profile("in", { cycles = 0 }, inProfile) or nil
  local event, limit = host:service(20), 0
  while event and limit < 50 do
    if inProfile then inProfile.args.cycles = inProfile.args.cycles + 1 end

    local sessionID = event.peer:connect_id()
    local client = getClient(sessionID)

    if event.type == "receive" then
      local success, encoded = pcall(ld.decompress, "string", options.compressionFunction, event.data)
      if not success then
        POST("log", "Could not decompress incoming data from "..sessionID..(client.username and " known as "..client.username or ""))
        if not client.loggedIn then
          removeClient(sessionID)
          client.peer:disconnect_now(enum.disconnect.badlogin)
        end
        goto continue
      end
      if client.loggedIn then
        POST(enum.packetType.receive, sessionID, encoded)
      else
        local success, uid = validLogin(client, encoded)
        if not success then
          removeClient(sessionID)
          client.peer:disconnect_now(enum.disconnect.badlogin)
          goto continue
        end
        POST(enum.packetType.login, sessionID, serialize.encode({ username = client.username, uid = client.uid }))
        channelIn:push({ -- tell client it is accepted, and their uid if they're a new user
          sessionID,
          serialize.encode(enum.packetType.login, uid)
        })
      end
    elseif event.type == "disconnect" then
      removeClient(sessionID)
      if client.loggedIn then
        POST(enum.packetType.disconnect, sessionID)
      end
    elseif event.type == "connect" then
      if event.data ~= settings.pin then
        removeClient(sessionID)
        client.peer:disconnect_now(enum.disconnect.badlogin)
        goto continue
      end
      client.sessionID = sessionID
      client.loggedIn = false
      client.peer = event.peer
    end
    ::continue::
    event = host:check_events()
    limit = limit + 1
  end
  if inProfile then inProfile:stop() end

  -- SEND
  outProfile = appleCake and appleCake.isActive and appleCake.profile("out", { cycles = 0}, outProfile) or nil
  local command, limit = channelIn:demand(1/100), 0
  while command and limit < 50 do
    if outProfile then outProfile.args.cycles = outProfile.args.cycles + 1 end
    if command == "quit" then
      host:destroy()
      outProfile:stop()
      return
    end
    if type(command) ~= "table" then
      POST("log", "Retrieved command to send was not of type table! It was "..type(command))
      goto continue
    end
    -- abstract target, channel and data from incoming
    local target = command[1]
    local data = command[2]
    local channel = enum.channel.default
    local flags = "reliable"
    if target == "channel" then
      channel = command[2]
      if channel == enum.channel.unreliable then
        flags = "unreliable"
      elseif channel == enum.channel.unsequenced then
        flags = "unsequenced"
      end
      target = command[3]
      data = command[4]
    end
    -- compress data
    local compressData
    if data and data ~= enum.packetType.disconnect then
      local success
      success, compressData = pcall(ld.compress, "data", options.compressionFunction, data)
      if not success then
        if target == "all" then
          POST("log", "Could not compress outgoing data to all")
        else
          local client = getClient(target, false)
          POST("log", "Could not compress outgoing data to "..tostring(target)..(client and client.username and " known as "..client.username or ""))
        end
        goto continue
      end
      if appleCake and appleCake.isActive then
        appleCake.mark("Compressed", "p", { size = data:getSize(), compressedSize = compressData:getSize() })
      end
    end
    -- send to target
    if target == "all" then
      for _, client in pairs(clients) do
        if client.loggedIn then
          client.peer:send(data:getFFIPointer(), data:getSize(), channel, flags)
        end
      end
    else
      local client = getClient(target, false)
      if not client then
        POST("log", "Network target is not valid "..tostring(target))
        goto continue
      end
      if command[2] == enum.packetType.disconnect then
        local reason = tonumber(command[3]) or enum.disconnect.normal
        client.peer:disconnect(reason)
        goto continue
      end
      
      client.peer:send(compressData:getFFIPointer(), compressData:getSize(), channel, flags)
    end
    ::continue::
    command = channelIn:pop()
    limit = limit + 1
  end
  if outProfile then outProfile:stop() end
  -- AC
  if appleCake and appleCake.isActive then
    appleCake.flush()
  end
end