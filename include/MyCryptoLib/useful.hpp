template <typename T>
inline T & make_rw(const T & target) {
    return const_cast<T>(target);
}
