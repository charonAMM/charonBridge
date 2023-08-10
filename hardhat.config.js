/** @type import('hardhat/config').HardhatUserConfig */
require('@nomiclabs/hardhat-ethers')
require('@nomiclabs/hardhat-waffle')
require('dotenv').config()


task('hasher', 'Compile Poseidon hasher', () => {
  require('./scripts/compilePoseidon')
})

module.exports = {
  solidity: "0.8.17",
};
