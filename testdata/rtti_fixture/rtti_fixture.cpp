class Base {
public:
    virtual ~Base();
    virtual int value();
    int base_value;
};

Base::~Base() = default;
int Base::value() { return base_value; }

class Mid : public Base {
public:
    ~Mid() override;
    int value() override;
    int mid_value;
};

Mid::~Mid() = default;
int Mid::value() { return mid_value; }

class Other {
public:
    virtual ~Other();
    virtual int other_value();
    int other_data;
};

Other::~Other() = default;
int Other::other_value() { return other_data; }

class Child : public Mid, public Other {
public:
    ~Child() override;
    int value() override;
    int other_value() override;
    int child_value;
};

Child::~Child() = default;
int Child::value() { return child_value; }
int Child::other_value() { return child_value + 1; }

extern "C" int rtti_fixture() {
    Child child{};
    return child.value() + child.other_value();
}

int main() {
    return rtti_fixture();
}
