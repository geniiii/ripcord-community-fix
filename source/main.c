static __attribute__((constructor)) void OnAttach(void) {
    LoadHooks();
}
