const bcrypt = require('bcryptjs')

module.exports = {
    register: async (req, res) => {
        const db = req.app.get('db')

        const { name, email, password, admin } = req.body

        try {
            const [existingUser] = await db.get_user_by_email(email)

            if(existingUser) {
                return res.status(409).send('User already exists')
            }

            const salt = bcrypt.genSaltSync(10)
            const hash = bcrypt.hashSync(password, salt)

            const [ newUser ] = await db.register_user(name, email, hash, admin)

            req.session.user = newUser

            res.status(200).send(newUser)
        }
            catch(err) {
                console.log(err)
                return res.sendStatus(500)
            }
    },
    login: (req, res) => {
        const db = req.app('db')

        const { email, password } = req.body

        db.get_user_by_email(email)
            .then(([existingUser]) => {
                if(!existingUser) {
                    return res.status(403).send('Incorrect email')
                }

                const isAuthenticated = bcrypt.compareSync(password, existingUser.hash)

                if(!isAuthenticated) {
                    return res.status(403).send('Incorrect password')
                }

                delete existingUser.hash
                req.session.user = existingUser

                res.status(200).send(req.session.user)
            })
            .catch(err => console.log(err))
    },
    logout: (req, res) => {
        req.session.destroy()
        res.sendStatus(200)
    }
}