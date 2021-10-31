# Prerequistes 

## Freepascal

brew install fpc
or 
brew upgrade fpc

brew link --overwrite fpc

## LibSodium 

brew install libsodium

## CMake 


### Recreate CMake Files

cd ./bin
rm -rf *
cmake ..


### Build Program 

cd ./bin
cmake --build .
