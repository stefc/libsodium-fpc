program NaClTest;

{$linklib libsodium.23.dylib}

// brew install fpc
// or 
// brew upgrade fpc

// brew link --overwrite fpc

// fpc NaClTest -Mobjfpc -FEbin -Fl/usr/local/lib

// mkdir bin
// cd bin
// rm -rf 
// cmake ..

uses yProcs, libSodium;

const 
  // Sender's Key
  aliceSecret : TKey = (
    $77, $07, $6d, $0a, $73, $18, $a5, $7d,
    $3c, $16, $c1, $72, $51, $b2, $66, $45,
    $df, $4c, $2f, $87, $eb, $c0, $99, $2a,
    $b1, $77, $fb, $a5, $1d, $b9, $2c, $2a
    );


  // Receiver's Key
  bobSecret : TKey = (
    $5d, $ab, $08, $7e, $62, $4a, $8a, $4b, 
    $79, $e1, $7f, $8b, $83, $80, $0e, $e6, 
    $6f, $3b, $b1, $29, $26, $18, $b6, $fd, 
    $1c, $2f, $8b, $27, $ff, $88, $e0, $eb);

var 
  privKey, 
  pubAliceKey,
  pubBobKey : TKey;



begin
  privKey := createPrivateKey();
  writeln('A random new private Key:');
  writeln( ToHex( privKey ));

  writeln('Alice''s Priv Key:');
  writeln( ToHex( aliceSecret ));
  writeln('Bob''s Priv Key:');
  writeln( ToHex( bobSecret )); 
  writeln;

  pubAliceKey := createPublicKey(aliceSecret);
  writeln('Alice''s Pub Key:');
  writeln( ToHex( pubAliceKey ));
  // 8520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA4A98EAA9B4E6A 

  pubBobKey := createPublicKey(bobSecret);
  writeln('Bob''s Pub Key:');
  writeln( ToHex( pubBobKey ));
  // DE9EDB7D7B7DC1B4D35B61C2ECE435373F8343C85B78674DADFC7E146F882B4F

end.