const path = require('path');
const TerserPlugin = require('terser-webpack-plugin');

module.exports = {
    mode: "production",
    entry: './src/index.js',
    output: {
        filename: 'main.js',
        path: path.resolve(__dirname, 'dist')
    },
    optimization: {
        minimize: true,
        minimizer: [
            new TerserPlugin({
                cache: true,
                parallel: true,
                sourceMap: true, // Must be set to true if using source-maps in production
                terserOptions: {
                    comments: false,
                    mangle: true,
                    keep_fnames: false,
                    keep_classnames: false
                },
                extractComments: 'all'
            }),
        ],
    },
    module: {
        rules: [{
                test: /\.html/,
                loader: 'file-loader?name=[name].[ext]',
            },
            {
                test: /\.css$/,
                use: ['style-loader', 'css-loader'],
            },
            {
                test: /\.(svg|gif|png|jpe?g)$/,
                loader: 'url-loader',
                options: {
                    limit: 100,
                    fallback: 'file-loader',
                    publicPath: '/img',
                    outputPath: '/img',
                },
            },
            {
                test: /\.scss$/,
                loader: 'style-loader!css-loader!sass-loader'
            },
            {
                test: /\.(woff(2)?|ttf|eot|svg)(\?v=\d+\.\d+\.\d+)?$/,
                use: [{
                    loader: 'url-loader',
                    options: {
                        limit: 100,
                        publicPath: '/fonts',
                        outputPath: '/fonts'
                    }
                }]
            }
        ],

    }
};