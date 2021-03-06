import commonjs from 'rollup-plugin-commonjs'
import resolve from 'rollup-plugin-node-resolve'
import sourcemaps from 'rollup-plugin-sourcemaps'
import json from 'rollup-plugin-json'

export default {
  input: 'dist/authorizer.js',
  output: {
    file: 'dist/authorizer.js',
    format: 'es'
  },
  plugins: [
    sourcemaps(),
    resolve({
      jsnext: true,
      main: true,
      browser: true
    }),
    commonjs({
      include: 'node_modules/**'
    }),
    json()
  ],
  external: [
    'rxjs/Observable'
    // "rxjs/add/operator/switchMap",
    // "rxjs/add/operator/map",
    // "markdown-it",
    // "lodash"
  ]
}
