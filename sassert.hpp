#ifndef SASSERT_H
#define SASSERT_H

template<bool assertion>
struct sassert;

template<>
struct sassert<true> {
};
    


#endif /* SASSERT_H */
