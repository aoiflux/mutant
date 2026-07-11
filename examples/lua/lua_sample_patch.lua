local f = io.open("examples/code.mut", "r")
if not f then
    error("could not open file")
end

local data = f:read("*a")
f:close()

print(data)
