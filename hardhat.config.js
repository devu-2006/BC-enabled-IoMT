require("@nomicfoundation/hardhat-toolbox");

// SAME compiler settings for baseline and optimized contracts -> fair gas comparison.
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: { optimizer: { enabled: true, runs: 200 } },
  },
  gasReporter: {
    enabled: process.env.REPORT_GAS === "true",
    currency: "USD",
  },
};
