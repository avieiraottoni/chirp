<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;
use Illuminate\Validation\Rules;
use Illuminate\View\View;

class NewPasswordController extends Controller
{
    /**
     * Exibe a view para redefinir a senha.
     *
     * @param Request $request - A requisição HTTP que contém os parâmetros necessários para o reset de senha.
     * @return View - Retorna a view que contém o formulário de redefinição de senha.
     */
    public function create(Request $request): View
    {
        // Renderiza a view 'auth.reset-password', passando a requisição como parâmetro.
        return view('auth.reset-password', ['request' => $request]);
    }

    /**
     * Processa a solicitação de criação de uma nova senha.
     *
     * @param Request $request - A requisição HTTP contendo os dados do formulário de redefinição de senha.
     * @return RedirectResponse - Redireciona o usuário após a tentativa de redefinição.
     *
     * @throws \Illuminate\Validation\ValidationException - Lança uma exceção se houver problemas de validação nos dados.
     */
    public function store(Request $request): RedirectResponse
    {
        // Valida os campos fornecidos pelo usuário:
        // 'token': O token de redefinição de senha é obrigatório.
        // 'email': O e-mail é obrigatório e deve ser válido.
        // 'password': A nova senha é obrigatória, precisa ser confirmada e seguir as regras padrão de segurança.
        $request->validate([
            'token' => ['required'], // Token para verificação da requisição.
            'email' => ['required', 'email'], // E-mail do usuário, obrigatório e válido.
            'password' => ['required', 'confirmed', Rules\Password::defaults()], // Senha obrigatória, confirmada e seguindo as regras padrão.
        ]);

        // Tentamos redefinir a senha do usuário. Se for bem-sucedido, a senha será atualizada no modelo de usuário
        // e persistida no banco de dados. Caso contrário, retornaremos o erro correspondente.
        $status = Password::reset(
            $request->only('email', 'password', 'password_confirmation', 'token'), // Pega os campos relevantes para o reset.
            function ($user) use ($request) {
                // Atualiza a senha do usuário e define um novo 'remember_token'.
                $user->forceFill([
                    'password' => Hash::make($request->password), // Criptografa a nova senha.
                    'remember_token' => Str::random(60), // Gera um novo token de "lembrar de mim".
                ])->save(); // Salva o usuário com as novas informações.

                // Dispara o evento PasswordReset para indicar que o usuário teve sua senha redefinida com sucesso.
                event(new PasswordReset($user));
            }
        );

        // Se a senha foi redefinida com sucesso, redireciona o usuário para a página de login e exibe uma mensagem de sucesso.
        // Caso contrário, retorna para a página anterior com os erros de validação.
        return $status == Password::PASSWORD_RESET
                    ? redirect()->route('login')->with('status', __($status)) // Redireciona para a tela de login com uma mensagem de status.
                    : back()->withInput($request->only('email')) // Volta para a página anterior com os dados de e-mail preenchidos.
                        ->withErrors(['email' => __($status)]); // Adiciona uma mensagem de erro relacionada ao e-mail.
    }
}
