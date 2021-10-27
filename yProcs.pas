unit yProcs;

interface 

function toHex(data:array of Byte): String; 

implementation

function toHex(data:array of Byte): String; 

  function ByteToHex(b:Byte):ShortString;
  const 
    Digits:array[0..15] of char='0123456789ABCDEF';
  begin
    Result := digits[b shr 4]+digits[b and $0F];
  end;

  var value : Byte;

begin 
  Result := '';
  for value in data do 
    Result := Result + ByteToHex(value);
end; 

end.