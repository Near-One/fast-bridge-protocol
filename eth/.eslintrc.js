module.exports = {
    env: {
        browser: false,
        es2021: true,
        mocha: true,
        node: true
    },
    plugins: ["node", "prettier"],
    extends: ["eslint:recommended", "plugin:node/recommended", "plugin:prettier/recommended", "prettier"],
    globals: {
        abi: false, 
        artifacts: false,
        contract: false
    },
    parserOptions: {
        sourceType: "module"
    },
    root: true,
    rules: {
        "quotes": ["error", "double"],
        "eol-last": ["error"],
        "max-len": [
            "error",
            { "code": 140, "ignoreUrls": true }
        ],
        "no-trailing-spaces": ["error"]
    },
    overrides: [
        {
            files: ["hardhat.config.js"]
        }
    ]
};
