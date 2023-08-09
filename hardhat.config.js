/** @type import('hardhat/config').HardhatUserConfig */

task('hasher', 'Compile Poseidon hasher', () => {
  require('./scripts/compilePoseidon')
})

module.exports = {
  solidity: "0.8.17",
};
