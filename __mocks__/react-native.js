/* Minimal react-native stub for the Node test environment. Only Platform is
 * referenced by the copied crypto sources (to branch web vs native storage). */
module.exports = {
  Platform: {
    OS: 'node',
    select: (spec) => (spec && (spec.default !== undefined ? spec.default : spec.native)),
  },
};
